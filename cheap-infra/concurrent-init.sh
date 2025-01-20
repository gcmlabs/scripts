#!/bin/bash

PUB_PRIV_RECORD_NAME="lb.test-jack-1-eu-north-1.jack.sandbox.soluzionifutura.it."
PRIV_ZONE_ID="Z0231449155I4P30H34YY"
ASG_NAME="test-jack-1-asg"
PRIVATE_IP="5.6.7.8"
export AWS_REGION="eu-north-1"
export AWS_PROFILE="sandbox"

echo "UPDATE PRIVATE DNS"
echo ""

# Get the record A of the hosted zone
PRIVATE_RECORD_IPS=$(aws route53 list-resource-record-sets \
    --hosted-zone-id $PRIV_ZONE_ID \
    --query "ResourceRecordSets[?(Name == '$PUB_PRIV_RECORD_NAME') && (Type == 'A')].ResourceRecords" \
    --output text)

PRIVATE_IPS_UPSERT="[]"

# If the record A is found
if [[ -n "$PRIVATE_RECORD_IPS" ]]; then

    echo "Record A found for $PUB_PRIV_RECORD_NAME"
    echo ""

    PRIVATE_RECORD_IPS=$(echo $PRIVATE_RECORD_IPS | tr ' ' ',')

    echo "Private IPs of record A: $PRIVATE_RECORD_IPS"
    echo ""

    # Get the running instances with the same private IPs
    INSTANCE_IDS_FROM_PRIV_IP=$(aws ec2 describe-instances \
        --filters "Name=private-ip-address,Values=$PRIVATE_RECORD_IPS" "Name=instance-state-name,Values=running" \
        --query "Reservations[].Instances[].InstanceId" \
        --output json)

    # If running instances are found with the private IPs of the record A
    if [[ "$INSTANCE_IDS_FROM_PRIV_IP" != "[]" ]]; then
        
        # Parse the JSON array to get the instance IDs separated by space
        INSTANCE_IDS_FROM_PRIV_IP=$(echo $INSTANCE_IDS_FROM_PRIV_IP | jq -r '.[]' | tr '\n' ' ')

        echo "Running instance IDs: $INSTANCE_IDS_FROM_PRIV_IP"
        echo ""

        # Get the healthy and InService instance Ids from the ASG
        HEALTHY_INSTANCE_IDS=$(aws autoscaling describe-auto-scaling-instances \
            --instance-ids $INSTANCE_IDS_FROM_PRIV_IP \
            --query "AutoScalingInstances[?(LifecycleState == 'InService') && (HealthStatus == 'HEALTHY') && (AutoScalingGroupName == '$ASG_NAME')][].InstanceId" \
            --output json)

        # If healthy and InService instances are found in the ASG
        if [[ "$HEALTHY_INSTANCE_IDS" != "[]" ]]; then

            # Parse the JSON array to get the instance IDs separated by space
            HEALTHY_INSTANCE_IDS=$(echo $HEALTHY_INSTANCE_IDS | jq -r '.[]' | tr '\n' ' ')

            echo "Healthy instances Ids in the ASG: $HEALTHY_INSTANCE_IDS"
            echo ""

            # Get the private IPs of the healthy and InService instances
            HEALTHY_INSTANCES_PRIVATE_IPS=$(aws ec2 describe-instances \
                --instance-ids $HEALTHY_INSTANCE_IDS \
                --query "Reservations[].Instances[].PrivateIpAddress" \
                --output json)

            # Add the private IPs to the upsert variable
            PRIVATE_IPS_UPSERT=$HEALTHY_INSTANCES_PRIVATE_IPS

            # Parse the JSON array to get the private IPs separated by space
            HEALTHY_INSTANCES_PRIVATE_IPS=$(echo $HEALTHY_INSTANCES_PRIVATE_IPS | jq -r '.[]' | tr '\n' ' ')

            echo "Private IPs of healthy instances: $HEALTHY_INSTANCES_PRIVATE_IPS"
            echo ""

        else 
            echo "No healthy and InService instances found in the ASG, upsert only the current instance private IP"
            echo ""
        fi
    else 
        echo "No running instances found for the private IPs of record A, upsert only the current instance private IP"
        echo ""
    fi

else
    echo "No private record A found for $PUB_PRIV_RECORD_NAME, create a new record A with the current instance private IP"
    echo ""
fi

PRIVATE_IPS_UPSERT=$(echo $PRIVATE_IPS_UPSERT | jq --arg ip "$PRIVATE_IP" 'map({Value: .}) | . + [{Value: $ip}]')

echo "Private IPs to upsert: $PRIVATE_IPS_UPSERT"
echo ""

# Upsert the record A with the private IPs
CHANGE_BATCH_PRIVATE_RECORD=$(cat <<EOF
{
    "Changes": [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "$PUB_PRIV_RECORD_NAME",
                "Type": "A",
                "TTL": 60,
                "ResourceRecords": $PRIVATE_IPS_UPSERT
            }
        }
    ]
}
EOF
)

echo "PRIVATE CHANGE BATCH: $CHANGE_BATCH_PRIVATE_RECORD"
echo ""

aws route53 change-resource-record-sets \
    --hosted-zone-id "$PRIV_ZONE_ID" \
    --change-batch "$CHANGE_BATCH_PRIVATE_RECORD"



PUBLIC_IP="11.10.10.10"
PARAMETER_NAME="hostedZoneId-jack"
DOMAIN_NAME="jack.sandbox.soluzionifutura.it."

echo "UPDATE PUBLIC DNS"
echo ""

# Retrieve Hosted Zone ID from SSM Parameter Store (will return empty string if parameter does not exist)
PUBLIC_ZONE_ID=$(aws ssm get-parameter --name $PARAMETER_NAME --query "Parameter.Value" --output text)
echo "Public Zone ID: $PUBLIC_ZONE_ID"
echo ""

ACTUAL_ZONE_ID=""

# Find the hosted zone ID from the domain name if not specified
if [[ "$PUBLIC_ZONE_ID" == "None" || "$PUBLIC_ZONE_ID" == "" ]]; then
    echo "No hosted zone ID specified, fetching from the domain name"
    echo ""

    # List all the public hosted zones with the specified domain name
    PUB_HOSTED_ZONES=$(aws route53 list-hosted-zones-by-name \
        --dns-name "$DOMAIN_NAME" \
        --query "HostedZones[?(Name=='$DOMAIN_NAME') && (Config.PrivateZone == \`false\`)].Id" \
        --output json | jq 'map(ltrimstr("/hostedzone/"))')
    
    ARRAY_LENGTH=$(echo $PUB_HOSTED_ZONES | jq 'length')

    if [[ $ARRAY_LENGTH -eq 0 ]]; then
        echo "No hosted zones found with the specified domain ($DOMAIN_NAME), make sure to create one"
        echo ""

    elif [[ $ARRAY_LENGTH -eq 1 ]]; then
        ACTUAL_ZONE_ID=$(echo $PUB_HOSTED_ZONES | jq -r '.[0]')
        echo "One hosted zone found with specified domain ($DOMAIN_NAME): $ACTUAL_ZONE_ID"
        echo ""

        # Update the hosted zone ID in the SSM Parameter Store
        UPDATE_PARAMETER=$(aws ssm put-parameter --name $PARAMETER_NAME --value $ACTUAL_ZONE_ID --type "String" --overwrite)
        echo "Hosted zone ID updated in the SSM Parameter Store"
        echo ""

    else
        # Parse the JSON array to get the HZ Ids separated by space
        PUB_HOSTED_ZONES_STRING=$(echo $PUB_HOSTED_ZONES | jq -r '.[]' | tr '\n' ' ')
        echo "Hosted zones with specified domain name: $PUB_HOSTED_ZONES_STRING"
        echo ""

        # Resolve the NS records of the domain to check if they match the NS records of the hosted zone in Route53
        DOMAIN_NS_RECORDS=$(dig +short NS $DOMAIN_NAME)
        
        # If an error occurred, log the error message, otherwhise check if the NS records match
        if [[ -z "$DOMAIN_NS_RECORDS" ]]; then
            echo "No NS records found for the domain $DOMAIN_NAME, check the following logs (error occurred or domain does not exist)"
            echo ""
            dig NS $DOMAIN_NAME
        else
            # Create a sorted json array of NS records
            DOMAIN_NS_RECORDS_SORTED=$(echo $DOMAIN_NS_RECORDS | jq -R 'split(" ") | map(rtrimstr(".")) | sort')

            # Parse the JSON array to get the domain NS records separated by space
            DOMAIN_NS_RECORDS_STRING=$(echo $DOMAIN_NS_RECORDS_SORTED | jq -r '.[]' | tr '\n' ' ')
            echo "NS records of the domain $DOMAIN_NAME: $DOMAIN_NS_RECORDS_STRING"
            echo ""

            # Iterate over the hosted zones to find the one with matching NS records
            for hz_id in $PUB_HOSTED_ZONES_STRING; do

                ZONE_NS_RECORDS_SORTED=$(aws route53 get-hosted-zone \
                    --id "$hz_id" \
                    --query "DelegationSet.NameServers" \
                    --output json | jq 'sort')
                
                # Parse the JSON array to get the domain NS records separated by space
                ZONE_NS_RECORDS_STRING=$(echo $ZONE_NS_RECORDS_SORTED | jq -r '.[]' | tr '\n' ' ')
                echo "Delegation set for Hosted Zone $hz_id: $ZONE_NS_RECORDS_STRING"
                echo ""
                

                if [[ "$DOMAIN_NS_RECORDS_SORTED" == "$ZONE_NS_RECORDS_SORTED" ]]; then
                    ACTUAL_ZONE_ID=$hz_id
                    echo "The NS servers of the domain $DOMAIN_NAME match the NS servers of the hosted zone $hz_id"
                    echo ""

                    # Update the hosted zone ID in the SSM Parameter Store
                    UPDATE_PARAMETER=$(aws ssm put-parameter --name $PARAMETER_NAME --value $ACTUAL_ZONE_ID --type "String" --overwrite)
                    echo "Hosted zone ID updated in the SSM Parameter Store"
                    echo ""
                    break
                else
                    echo "The NS servers of the domain $DOMAIN_NAME do not match the NS servers of the hosted zone $hz_id"
                    echo ""
                fi
            done

            if [[ -z "$ACTUAL_ZONE_ID" ]]; then
                echo "No suitable hosted zone found, fix delegation to the correct nameservers for $DOMAIN_NAME"
                echo ""
            else
                echo "Found actual hosted zone ID: $ACTUAL_ZONE_ID"
                echo ""
            fi
        fi
    fi
else 
    echo "Hosted zone ID specified in the template: $PUBLIC_ZONE_ID"
    echo ""
    ACTUAL_ZONE_ID=$PUBLIC_ZONE_ID
fi

if [[ -z "$ACTUAL_ZONE_ID" ]]; then
    echo "No actual hosted zone ID found, doing nothing"
    echo ""
else

    # Get the record A of the hosted zone
    PUBLIC_RECORD_IPS=$(aws route53 list-resource-record-sets \
        --hosted-zone-id $ACTUAL_ZONE_ID \
        --query "ResourceRecordSets[?(Name == '$PUB_PRIV_RECORD_NAME') && (Type == 'A')].ResourceRecords" \
        --output text)


    PUBLIC_IPS_UPSERT="[]"

    # If the record A is found
    if [[ -n "$PUBLIC_RECORD_IPS" ]]; then

        echo "Record A found for $PUB_PRIV_RECORD_NAME"
        echo ""

        PUBLIC_RECORD_IPS=$(echo $PUBLIC_RECORD_IPS | tr ' ' ',')

        echo "Public IPs of record A: $PUBLIC_RECORD_IPS"
        echo ""

        # Get the running instances with the same public IPs
        INSTANCE_IDS_FROM_PUB_IP=$(aws ec2 describe-instances \
            --filters "Name=ip-address,Values=$PUBLIC_RECORD_IPS" "Name=instance-state-name,Values=running" \
            --query "Reservations[].Instances[].InstanceId" \
            --output json)

        # If running instances are found with the public IPs of the record A
        if [[ "$INSTANCE_IDS_FROM_PUB_IP" != "[]" ]]; then
            
            # Parse the JSON array to get the instance IDs separated by space
            INSTANCE_IDS_FROM_PUB_IP=$(echo $INSTANCE_IDS_FROM_PUB_IP | jq -r '.[]' | tr '\n' ' ')

            echo "Running instance IDs: $INSTANCE_IDS_FROM_PUB_IP"
            echo ""

            # Get the healthy and InService instance Ids from the ASG
            HEALTHY_INSTANCE_IDS=$(aws autoscaling describe-auto-scaling-instances \
                --instance-ids $INSTANCE_IDS_FROM_PUB_IP \
                --query "AutoScalingInstances[?(LifecycleState == 'InService') && (HealthStatus == 'HEALTHY') && (AutoScalingGroupName == '$ASG_NAME')][].InstanceId" \
                --output json)

            # If healthy and InService instances are found in the ASG
            if [[ "$HEALTHY_INSTANCE_IDS" != "[]" ]]; then

                # Parse the JSON array to get the instance IDs separated by space
                HEALTHY_INSTANCE_IDS=$(echo $HEALTHY_INSTANCE_IDS | jq -r '.[]' | tr '\n' ' ')

                echo "Healthy instances Ids in the ASG: $HEALTHY_INSTANCE_IDS"
                echo ""

                # Get the private IPs of the healthy and InService instances
                HEALTHY_INSTANCES_PUBLIC_IPS=$(aws ec2 describe-instances \
                    --instance-ids $HEALTHY_INSTANCE_IDS \
                    --query "Reservations[].Instances[].PublicIpAddress" \
                    --output json)

                # Add the public IPs to the upsert variable
                PUBLIC_IPS_UPSERT=$HEALTHY_INSTANCES_PUBLIC_IPS

                # Parse the JSON array to get the public IPs separated by space
                HEALTHY_INSTANCES_PUBLIC_IPS=$(echo $HEALTHY_INSTANCES_PUBLIC_IPS | jq -r '.[]' | tr '\n' ' ')

                echo "Public IPs of healthy instances: $HEALTHY_INSTANCES_PUBLIC_IPS"
                echo ""

            else 
                echo "No healthy and InService instances found in the ASG, upsert only the current instance public IP"
                echo ""
            fi
        else 
            echo "No running instances found for the public IPs of record A, upsert only the current instance public IP"
            echo ""
        fi

    else
        echo "No public record A found for $PUB_PRIV_RECORD_NAME, create a new record A with the current instance public IP"
        echo ""
    fi

    PUBLIC_IPS_UPSERT=$(echo $PUBLIC_IPS_UPSERT | jq --arg ip "$PUBLIC_IP" 'map({Value: .}) | . + [{Value: $ip}]')

    echo "Public IPs to upsert: $PUBLIC_IPS_UPSERT"
    echo ""

    # Upsert the record A with the public IPs
    CHANGE_BATCH_PUBLIC_RECORD=$(cat <<EOF
    {
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": "$PUB_PRIV_RECORD_NAME",
                    "Type": "A",
                    "TTL": 60,
                    "ResourceRecords": $PUBLIC_IPS_UPSERT
                }
            }
        ]
    }
EOF
    )

    echo "PUBLIC CHANGE BATCH: $CHANGE_BATCH_PUBLIC_RECORD"
    echo ""

    aws route53 change-resource-record-sets \
        --hosted-zone-id "$ACTUAL_ZONE_ID" \
        --change-batch "$CHANGE_BATCH_PUBLIC_RECORD"
fi
