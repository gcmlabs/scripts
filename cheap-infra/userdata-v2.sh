#!/bin/bash

# Update and install packages
dnf update -y
dnf install -y iptables-services sed wget jq tar bind-utils amazon-efs-utils

# Instance Metadata
TOKEN=$(curl --request PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 3600")
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id --header "X-aws-ec2-metadata-token: $TOKEN")
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region --header "X-aws-ec2-metadata-token: $TOKEN")

# Disable source/destination check
aws ec2 modify-instance-attribute --instance-id ${!INSTANCE_ID} --no-source-dest-check

# enable IP forwarding and NAT
ENI_IDENTIFIER=$(ip -4 addr show device-number-0.0 | grep -oP 'ens[0-9]+' | head -n1)

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.${!ENI_IDENTIFIER}.send_redirects=0

echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/100-custom.conf
echo 'net.ipv4.conf.${!ENI_IDENTIFIER}.send_redirects=0' >> /etc/sysctl.d/100-custom.conf

# create custom rules to allow NAT
iptables -t nat -A POSTROUTING -s ${pPrivateSubnet1CIDR} ! -o docker0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s ${pPrivateSubnet2CIDR} ! -o docker0 -j MASQUERADE
iptables -I DOCKER-USER -s ${pPrivateSubnet1CIDR} -j ACCEPT
iptables -I DOCKER-USER -s ${pPrivateSubnet2CIDR} -j ACCEPT
iptables -I DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow ICMP based traffic
iptables -D INPUT $(iptables -L INPUT --line-numbers | grep icmp-host-prohibited | awk '{print $1}')
iptables -D FORWARD $(iptables -L FORWARD --line-numbers | grep icmp-host-prohibited | awk '{print $1}')

# Edit Iptables service configuration file
sed -i 's/IPTABLES_SAVE_ON_STOP="no"/IPTABLES_SAVE_ON_STOP="yes"/' /etc/sysconfig/iptables-config
sed -i 's/IPTABLES_SAVE_ON_RESTART="no"/IPTABLES_SAVE_ON_RESTART="yes"/' /etc/sysconfig/iptables-config

# Save the rules before starting the service
iptables-save > /etc/sysconfig/iptables

# Start and enable the iptables service
systemctl start iptables
systemctl enable iptables

# Mount EFS for LetsEncrypt Certificates of Traefik
mkdir -p /letsencrypt/traefik
echo '${EfsLetsEncrypt} /letsencrypt/traefik efs _netdev,noresvport,tls 0 0' >> /etc/fstab
mount -a

# Tag volumes
ROOT_VOLUME_ID=$(aws ec2 describe-volumes --region ${!REGION} --filters Name=attachment.instance-id,Values="${!INSTANCE_ID}" Name=attachment.device,Values=/dev/xvda | jq -r '.Volumes[0].Attachments[0].VolumeId')
aws ec2 create-tags --resources ${!ROOT_VOLUME_ID} --region ${!REGION} --tags Key=Name,Value=bastion

# Create SwapFile with fallocate
fallocate -l 8G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
echo "$(swapon -s)"
echo ""

# ECS Config
cat << EOF >> /etc/ecs/ecs.config
ECS_CLUSTER=${AWS::StackName}-cluster
ECS_ENGINE_TASK_CLEANUP_WAIT_DURATION=1m
ECS_CONTAINER_STOP_TIMEOUT=10s
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
EOF

# Check Route Table and optionally create or replace route
PRIVATE_ROUTE_TABLE=${PrivateRouteTable}
ROUTE_OUTPUT=$(aws ec2 describe-route-tables --route-table-ids $PRIVATE_ROUTE_TABLE --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0']" --output json)
echo "ROUTE OUTPUT: $ROUTE_OUTPUT"
echo ""

if [[ "$ROUTE_OUTPUT" == "[]" ]]; then
    aws ec2 create-route --route-table-id $PRIVATE_ROUTE_TABLE --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
    echo "Route created" #TODO if create command exit with error do the same with replace command 
    echo ""

elif echo "$ROUTE_OUTPUT" | grep -q "blackhole"; then
    aws ec2 replace-route --route-table-id $PRIVATE_ROUTE_TABLE --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
    echo "Blackhole found. Route replaced"
    echo ""

else
    NAT_INSTANCE_ID=$(echo "$ROUTE_OUTPUT" | jq -r '.[0].InstanceId')
    NAT_INSTANCE_LIFECYCLE_STATE=$(aws autoscaling describe-auto-scaling-instances --instance-ids $NAT_INSTANCE_ID --query "AutoScalingInstances[0].LifecycleState" --output text)
    if ! [[ "$NAT_INSTANCE_LIFECYCLE_STATE" == "InService" ]]; then
        aws ec2 replace-route --route-table-id $PRIVATE_ROUTE_TABLE --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
        echo "Instance $NAT_INSTANCE_ID is not in service. Route replaced"
        echo ""
    else
    echo "Route is healthy"
    echo ""
    fi
fi

# Traefik Install and Config based on architecture
echo "Architecture: ${Architecture}"
if [[ "${Architecture}" == "arm" ]]; then
    wget -q https://github.com/traefik/traefik/releases/download/v3.2.3/traefik_v3.2.3_linux_arm64.tar.gz
    tar -xzf traefik_v3.2.3_linux_arm64.tar.gz
else
    wget -q https://github.com/traefik/traefik/releases/download/v3.2.3/traefik_v3.2.3_linux_amd64.tar.gz
    tar -xzf traefik_v3.2.3_linux_amd64.tar.gz
fi

rm traefik_v3.2.3_linux_*
mv traefik /usr/bin
chown root:root /usr/bin/traefik
chmod 755 /usr/bin/traefik
mkdir /etc/traefik
cat << EOF > /etc/traefik/traefik.yml

certificatesResolvers:
  myresolver:
    acme:
      email: "${pEmail}"
      storage: "/letsencrypt/traefik/acme.json"
      httpChallenge:
        entryPoint: web

providers:
  ecs:
    autoDiscoverClusters: false
    clusters:
      - ${AWS::StackName}-cluster
    healthyTasksOnly: true
    exposedByDefault: false
    refreshSeconds: 15
  file:
    filename: /etc/traefik/traefik.yml
    watch: true

api:
  dashboard: true
  insecure: true
  debug: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true

  websecure:
    address: ":443"

log: # ERROR for prod, DEBUG for staging
  level: ${TraefikLogsLevel}
  noColor: true
  filePath: "/var/log/traefik"
EOF


cat << EOF > /lib/systemd/system/traefik.service
[Unit]
Description=traefik service
After=network-online.target

[Service]
Type=notify
User=root
Group=root
Restart=always
ExecStart=/usr/bin/traefik --configFile=/etc/traefik/traefik.yml

[Install]
WantedBy=multi-user.target
EOF

systemctl enable traefik
systemctl start traefik


### DNS CONFIGURATION ###

# DNS Variables
PRIV_ZONE_ID=${PrivateHostedZone}
RECORD_NAME="lb.${AWS::StackName}-${AWS::Region}.${pDomainName}."
ASG_NAME=${AWS::StackName}-asg
INSTANCE_PRIV_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 --header "X-aws-ec2-metadata-token: $TOKEN")
DOMAIN_NAME="${pDomainName}."
INSTANCE_PUB_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 --header "X-aws-ec2-metadata-token: $TOKEN")
PARAMETER_NAME=${PublicHostedZoneIdParameter}

PRIVATE_FILTER_NAME="private-ip-address"
PRIVATE_IP_QUERY="PrivateIpAddress"
PUBLIC_FILTER_NAME="ip-address"
PUBLIC_IP_QUERY="PublicIpAddress"

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

    aws route53 change-resource-record-sets \
        --hosted-zone-id "$ZONE_ID" \
        --change-batch "$CHANGE_BATCH"
}

### PRIVATE DNS RECORDS ###
echo "UPDATE PRIVATE DNS"
echo ""

for i in {0..4}; do
    if [[ $i -eq 0 ]]; then
        echo "Upserting record..."
    fi
    updateDns "$INSTANCE_PRIV_IP" "$PRIV_ZONE_ID" "$PRIVATE_FILTER_NAME" "$PRIVATE_IP_QUERY"
    sleep 2
    RECORD_IPS=$(aws route53 list-resource-record-sets \
    --hosted-zone-id $PRIV_ZONE_ID \
    --query "ResourceRecordSets[?(Name == '$RECORD_NAME') && (Type == 'A')].ResourceRecords" \
    --output text)
    if echo $RECORD_IPS | grep -q $INSTANCE_PRIV_IP; then
        echo "Record upsert successful."
        break
    else
        if [[ $i -eq 4 ]]; then
            echo "Record upsert failed too many times, aborting."
        else
            echo "Record upsert failed, retrying..."
        fi
    fi
done

### PUBLIC DNS RECORDS ###
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
    for i in {0..4}; do
        if [[ $i -eq 0 ]]; then
            echo "Creating record..."
        fi
        updateDns "$INSTANCE_PUB_IP" "$ACTUAL_ZONE_ID" "$PUBLIC_FILTER_NAME" "$PUBLIC_IP_QUERY"
        sleep 2
        RECORD_IPS=$(aws route53 list-resource-record-sets \
        --hosted-zone-id $ACTUAL_ZONE_ID \
        --query "ResourceRecordSets[?(Name == '$RECORD_NAME') && (Type == 'A')].ResourceRecords" \
        --output text)
        if echo $RECORD_IPS | grep -q $INSTANCE_PUB_IP; then
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
fi

# Add tag so that the instance can be evalued as healthy and running
aws ec2 create-tags --resources $INSTANCE_ID --tags Key=Init,Value=Complete