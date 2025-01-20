#!/bin/bash

# Private DNS Variables
PRIV_HZ_ID=Z0698091HWMGDKWZARCL
PRIV_RECORD_NAME="brutto.can.dedio"

# Get instance private IP from metadata
TOKEN=$(curl --request PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 3600")
INSTANCE_PRIV_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 --header "X-aws-ec2-metadata-token: $TOKEN")

# Get only the HEALTHY instances from the ASG
ASG_NAME="vpc-bastion-asg"
HEALTHY_INSTANCES_ARRAY=($(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names $ASG_NAME --query "AutoScalingGroups[0].Instances[?HealthStatus=='Healthy'].InstanceId" --output text))
echo "HEALTHY INSTANCES ${HEALTHY_INSTANCES_ARRAY[@]}"

# Get the private IPs of the HEALTHY instances that have completed the init phase
PRIV_IPS_ARRAY=($(aws ec2 describe-instances --instance-ids ${HEALTHY_INSTANCES_ARRAY[@]} --query "Reservations[0].Instances[?Tags[]].PrivateIpAddress" --output text))

echo "PRIV_IPS_ARRAY ${PRIV_IPS_ARRAY[@]}"

for instance_id in "${HEALTHY_INSTANCES_ARRAY[@]}"; do

    PRIV_IP=$(aws ec2 describe-instances --instance-ids $instance_id --filter Name=tag:Init,Values=Completed --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)

    if [[ "$PRIV_IP" == "None" ]]; then
        echo "Instance $instance_id init phase still running. Skipping..."
        continue
    fi

    PRIV_IPS_ARRAY+=("$PRIV_IP")
done

# Format the values for the Route53 change-resource-record-sets command
VALUES_ARRAY=()

for value in "${PRIV_IPS_ARRAY[@]}"; do
    VALUES_ARRAY+=("{\"Value\": \"$value\"}")
done

VALUES_ARRAY+=("{\"Value\": \"$INSTANCE_PRIV_IP\"}")

VALUES_JSON=$(printf '%s\n' "${VALUES_ARRAY[@]}" | jq -s .)

# UPSERT the private record in Route53
CHANGE_BATCH=$(cat <<EOF
{
    "Changes": [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "$PRIV_RECORD_NAME",
                "Type": "A",
                "TTL": 60,
                "ResourceRecords": $VALUES_JSON
            }
        }
    ]
}
EOF
)

aws route53 change-resource-record-sets --hosted-zone-id "$PRIV_HZ_ID" --change-batch "$CHANGE_BATCH"


