#!/bin/bash

export AWS_PROFILE="sandbox"
export AWS_REGION="eu-north-1"
PUBLIC_ZONE_ID="Z056703232KBLB4HWOU2"
PRIVATE_ZONE_ID="Z0417833206XTZCZWT9F3"
PUBLIC_INSTANCE_IP="2.1.1.1"
PRIVATE_INSTANCE_IP="3.2.2.2"
RECORD_NAME="jack.lb.jack-cheap-infra-eu-north-1.jack.sandbox.soluzionifutura.it."
PRIVATE_FILTER_NAME="private-ip-address"
PRIVATE_IP_QUERY="PrivateIpAddress"
PUBLIC_FILTER_NAME="ip-address"
PUBLIC_IP_QUERY="PublicIpAddress"
ASG_NAME="jack-cheap-infra-asg"

updateDns () {

    local INSTANCE_IP=$1
    local ZONE_ID=$2
    local FILTER_NAME=$3
    local IP_QUERY=$4
    

    # Get the record A of the hosted zone
    RECORD_IPS=$(aws route53 list-resource-record-sets \
        --hosted-zone-id $ZONE_ID \
        --query "ResourceRecordSets[?(Name == '$RECORD_NAME') && (Type == 'A')].ResourceRecords" \
        --output text)

    IPS_UPSERT="[]"

    # If the record A is found
    if [[ -n "$RECORD_IPS" ]]; then

        echo "Record A found for $RECORD_NAME"
        echo ""

        RECORD_IPS=$(echo $RECORD_IPS | tr ' ' ',')

        echo "IPs of record A: $RECORD_IPS"
        echo ""

        # Get the running instances with the same IPs
        INSTANCE_IDS_FROM_IP=$(aws ec2 describe-instances \
            --filters "Name=$FILTER_NAME,Values=$RECORD_IPS" "Name=instance-state-name,Values=running" \
            --query "Reservations[].Instances[].InstanceId" \
            --output json)

        # If running instances are found with the IPs of the record A
        if [[ "$INSTANCE_IDS_FROM_IP" != "[]" ]]; then
            
            # Parse the JSON array to get the instance IDs separated by space
            INSTANCE_IDS_FROM_IP=$(echo $INSTANCE_IDS_FROM_IP | jq -r '.[]' | tr '\n' ' ')

            echo "Running instance IDs: $INSTANCE_IDS_FROM_IP"
            echo ""

            # Get the healthy and InService instance Ids from the ASG
            HEALTHY_INSTANCE_IDS=$(aws autoscaling describe-auto-scaling-instances \
                --instance-ids $INSTANCE_IDS_FROM_IP \
                --query "AutoScalingInstances[?(LifecycleState == 'InService') && (HealthStatus == 'HEALTHY') && (AutoScalingGroupName == '$ASG_NAME')][].InstanceId" \
                --output json)

            # If healthy and InService instances are found in the ASG
            if [[ "$HEALTHY_INSTANCE_IDS" != "[]" ]]; then

                # Parse the JSON array to get the instance IDs separated by space
                HEALTHY_INSTANCE_IDS=$(echo $HEALTHY_INSTANCE_IDS | jq -r '.[]' | tr '\n' ' ')

                echo "Healthy instances Ids in the ASG: $HEALTHY_INSTANCE_IDS"
                echo ""

                # Get the private IPs of the healthy and InService instances
                HEALTHY_INSTANCES_IPS=$(aws ec2 describe-instances \
                    --instance-ids $HEALTHY_INSTANCE_IDS \
                    --query "Reservations[].Instances[].$IP_QUERY" \
                    --output json)

                # Add the IPs to the upsert variable
                IPS_UPSERT=$HEALTHY_INSTANCES_IPS

                # Parse the JSON array to get the IPs separated by space
                HEALTHY_INSTANCES_IPS=$(echo $HEALTHY_INSTANCES_IPS | jq -r '.[]' | tr '\n' ' ')

                echo "IPs of healthy instances: $HEALTHY_INSTANCES_IPS"
                echo ""

            else 
                echo "No healthy and InService instances found in the ASG, upsert only the current instance IP"
                echo ""
            fi
        else 
            echo "No running instances found for the IPs of record A, upsert only the current instance IP"
            echo ""
        fi

    else
        echo "No record A found for $RECORD_NAME, create a new record A with the current instance IP"
        echo ""
    fi

    IPS_UPSERT=$(echo $IPS_UPSERT | jq --arg ip "$INSTANCE_IP" 'map({Value: .}) | . + [{Value: $ip}]')

    echo "IPs to upsert: $IPS_UPSERT"
    echo ""

    # Upsert the record A with the IPs
    CHANGE_BATCH=$(cat <<EOF
    {
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": "$RECORD_NAME",
                    "Type": "A",
                    "TTL": 60,
                    "ResourceRecords": $IPS_UPSERT
                }
            }
        ]
    }
EOF
    )

    echo "CHANGE BATCH: $CHANGE_BATCH"
    echo ""

    # aws route53 change-resource-record-sets \
    #     --hosted-zone-id "$ZONE_ID" \
    #     --change-batch "$CHANGE_BATCH"
}

for i in {0..4}; do

    if [[ $i -eq 0 ]]; then
        echo "Creating record..."
    fi

    updateDns "$PRIVATE_INSTANCE_IP" "$PRIVATE_ZONE_ID" "$PRIVATE_FILTER_NAME" "$PRIVATE_IP_QUERY"

    sleep 2

    RECORD_IPS=$(aws route53 list-resource-record-sets \
    --hosted-zone-id $PRIVATE_ZONE_ID \
    --query "ResourceRecordSets[?(Name == '$RECORD_NAME') && (Type == 'A')].ResourceRecords" \
    --output text)

    if echo $RECORD_IPS | grep -q $PRIVATE_INSTANCE_IP; then
        echo "Record creation successful."
        break
    else
        if [[ $i -eq 4 ]]; then
            echo "Record creation failed too many times, aborting."
        else
            echo "Record creation failed, retrying..."
        fi
    fi
done