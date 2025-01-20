#!/bin/bash

# Private DNS Variables
PRIV_HZ_ID=Z0698091HWMGDKWZARCL
PRIV_RECORD_NAME="maledetto.can.dedio"

# Get instance private IP from metadata
TOKEN=$(curl --request PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 3600")
INSTANCE_PRIV_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 --header "X-aws-ec2-metadata-token: $TOKEN")


# Get only the HEALTHY instances from the ASG
ASG_NAME="vpc-bastion-asg"
HEALTHY_INSTANCES=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names $ASG_NAME \
    --query "AutoScalingGroups[0].Instances[?HealthStatus=='Healthy'].InstanceId" \
    --output text)

echo "HEALTHY INSTANCES $HEALTHY_INSTANCES"
# Get the private IPs of the HEALTHY instances that have completed the init phase
if [[ -z "$HEALTHY_INSTANCES" || "$HEALTHY_INSTANCES" == "None" ]]; then
    HEALTHY_INSTANCES=""
fi

if [[ -n "$HEALTHY_INSTANCES" ]]; then
    INSTANCES_PRIV_IPS=$(aws ec2 describe-instances \
        --instance-ids $HEALTHY_INSTANCES \
        --query "Reservations[].Instances[?Tags[?Key=='Init' && Value=='Completed']].PrivateIpAddress" \
        --output text)

    echo "Completed Init Instances Private IPs: $INSTANCES_PRIV_IPS"

    if [[ -z "$INSTANCES_PRIV_IPS" ]]; then
        INSTANCES_PRIV_IPS=""
        PRIV_VALUES_JSON=$(jq -n --arg ip "$INSTANCE_PRIV_IP" '[{Value: $ip}]')
    else
        PRIV_VALUES_JSON=$(echo "$INSTANCES_PRIV_IPS" | \
            jq -R --arg ip "$INSTANCE_PRIV_IP" 'split("\n") | map(select(. != "" and . != "None")) | map({Value: .}) | . + [{Value: $ip}]')
    fi
else
    PRIV_VALUES_JSON=$(jq -n --arg ip "$INSTANCE_PRIV_IP" '[{Value: $ip}]')
fi

# UPSERT the private record in Route53
CHANGE_BATCH_PRIVATE_RECORD=$(cat <<EOF
{
    "Changes": [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "$PRIV_RECORD_NAME",
                "Type": "A",
                "TTL": 60,
                "ResourceRecords": $PRIV_VALUES_JSON
            }
        }
    ]
}
EOF
)

echo "PRIVATE CHANGE BATCH $CHANGE_BATCH_PRIVATE_RECORD"

aws route53 change-resource-record-sets --hosted-zone-id "$PRIV_HZ_ID" --change-batch "$CHANGE_BATCH_PRIVATE_RECORD"