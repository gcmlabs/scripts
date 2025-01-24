#!/bin/bash

# Install packages
dnf update -y
dnf install -y iptables-services sed wget jq tar bind-utils amazon-efs-utils
# Instance Metadata
TOKEN=$(curl --request PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 3600")
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id --header "X-aws-ec2-metadata-token: $TOKEN")
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region --header "X-aws-ec2-metadata-token: $TOKEN")
# Disable source/dest check
aws ec2 modify-instance-attribute --instance-id ${!INSTANCE_ID} --no-source-dest-check
# IP forwarding and NAT
ENI_IDENTIFIER=$(ip -4 addr show device-number-0.0 | grep -oP 'ens[0-9]+' | head -n1)
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.${!ENI_IDENTIFIER}.send_redirects=0
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/100-custom.conf
echo 'net.ipv4.conf.${!ENI_IDENTIFIER}.send_redirects=0' >> /etc/sysctl.d/100-custom.conf
# Custom rules to allow NAT
iptables -t nat -A POSTROUTING -s ${pPrivateSubnet1CIDR} ! -o docker0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s ${pPrivateSubnet2CIDR} ! -o docker0 -j MASQUERADE
iptables -I DOCKER-USER -s ${pPrivateSubnet1CIDR} -j ACCEPT
iptables -I DOCKER-USER -s ${pPrivateSubnet2CIDR} -j ACCEPT
iptables -I DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# Allow ICMP based traffic
iptables -D INPUT $(iptables -L INPUT --line-numbers | grep icmp-host-prohibited | awk '{print $1}')
iptables -D FORWARD $(iptables -L FORWARD --line-numbers | grep icmp-host-prohibited | awk '{print $1}')
# Persist Iptables config
sed -i 's/IPTABLES_SAVE_ON_STOP="no"/IPTABLES_SAVE_ON_STOP="yes"/' /etc/sysconfig/iptables-config
sed -i 's/IPTABLES_SAVE_ON_RESTART="no"/IPTABLES_SAVE_ON_RESTART="yes"/' /etc/sysconfig/iptables-config
# Save rules before starting service
iptables-save > /etc/sysconfig/iptables
systemctl start iptables
systemctl enable iptables
# EFS for LetsEncrypt
mkdir -p /letsencrypt/traefik
echo '${EfsLetsEncrypt} /letsencrypt/traefik efs _netdev,noresvport,tls 0 0' >> /etc/fstab
mount -a
# Tag volumes
ROOT_VOLUME_ID=$(aws ec2 describe-volumes --region ${!REGION} --filters Name=attachment.instance-id,Values="${!INSTANCE_ID}" Name=attachment.device,Values=/dev/xvda | jq -r '.Volumes[0].Attachments[0].VolumeId')
aws ec2 create-tags --resources ${!ROOT_VOLUME_ID} --region ${!REGION} --tags Key=Name,Value=bastion
# Swapfile
fallocate -l 8G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
echo "$(swapon -s)"
# ECS Config
cat << EOF >> /etc/ecs/ecs.config
ECS_CLUSTER=${AWS::StackName}-cluster
ECS_ENGINE_TASK_CLEANUP_WAIT_DURATION=1m
ECS_CONTAINER_STOP_TIMEOUT=10s
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
EOF
# Check Route Table
PRIVATE_ROUTE_TABLE=${PrivateRouteTable}
ROUTE_OUTPUT=$(aws ec2 describe-route-tables --route-table-ids $PRIVATE_ROUTE_TABLE --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0']" --output json)
echo -e "ROUTE OUTPUT: $ROUTE_OUTPUT\n"
if [[ "$ROUTE_OUTPUT" == "[]" ]]; then
    aws ec2 create-route --route-table-id $PRIVATE_ROUTE_TABLE --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
    echo -e "Route created\n" #TODO if create command exit with error do the same with replace command 
elif echo "$ROUTE_OUTPUT" | grep -q "blackhole"; then
    aws ec2 replace-route --route-table-id $PRIVATE_ROUTE_TABLE --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
    echo -e "Blackhole found. Route replaced\n"
else
    NAT_INSTANCE_ID=$(echo "$ROUTE_OUTPUT" | jq -r '.[0].InstanceId')
    NAT_INSTANCE_LIFECYCLE_STATE=$(aws autoscaling describe-auto-scaling-instances --instance-ids $NAT_INSTANCE_ID --query "AutoScalingInstances[0].LifecycleState" --output text)
    if ! [[ "$NAT_INSTANCE_LIFECYCLE_STATE" == "InService" ]]; then
        aws ec2 replace-route --route-table-id $PRIVATE_ROUTE_TABLE --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
        echo -e "Instance $NAT_INSTANCE_ID is not in service. Route replaced\n"
    else
    echo -e "Route is healthy\n"
    fi
fi
# Traefik Install
echo -e "Architecture: ${Architecture}\n"
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
    autoDiscoverClusters: true
  file:
    filename: "/etc/traefik/traefik.yml"
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
  level: DEBUG
  filePath: "/var/log/traefik"
  noColor: true
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
### DNS ###
# Variables
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
    # Get record A of hosted zone
    RECORD_IPS=$(aws route53 list-resource-record-sets \
        --hosted-zone-id $ZONE_ID \
        --query "ResourceRecordSets[?(Name == '$RECORD_NAME') && (Type == 'A')].ResourceRecords" \
        --output text)
    IPS_UPSERT="[]"
    # If record A is found
    if [[ -n "$RECORD_IPS" ]]; then
        echo -e "Record A found for $RECORD_NAME\n"
        RECORD_IPS=$(echo $RECORD_IPS | tr ' ' ',')
        echo -e "IPs of record A: $RECORD_IPS\n"
        # Get running instances with same IPs
        INSTANCE_IDS_FROM_IP=$(aws ec2 describe-instances \
            --filters "Name=$FILTER_NAME,Values=$RECORD_IPS" "Name=instance-state-name,Values=running" \
            --query "Reservations[].Instances[].InstanceId" \
            --output json)
        # If running instances are found with IPs of record A
        if [[ "$INSTANCE_IDS_FROM_IP" != "[]" ]]; then
            # Parse JSON array to get instance IDs separated by space
            INSTANCE_IDS_FROM_IP=$(echo $INSTANCE_IDS_FROM_IP | jq -r '.[]' | tr '\n' ' ')
            echo -e "Running instance IDs: $INSTANCE_IDS_FROM_IP\n"
            # Get healthy and InService instance Ids from ASG
            HEALTHY_INSTANCE_IDS=$(aws autoscaling describe-auto-scaling-instances \
                --instance-ids $INSTANCE_IDS_FROM_IP \
                --query "AutoScalingInstances[?(LifecycleState == 'InService') && (HealthStatus == 'HEALTHY') && (AutoScalingGroupName == '$ASG_NAME')][].InstanceId" \
                --output json)
            # If healthy and InService instances are found in ASG
            if [[ "$HEALTHY_INSTANCE_IDS" != "[]" ]]; then
                # Parse JSON array to get instance IDs separated by space
                HEALTHY_INSTANCE_IDS=$(echo $HEALTHY_INSTANCE_IDS | jq -r '.[]' | tr '\n' ' ')
                echo -e "Healthy instances Ids in the ASG: $HEALTHY_INSTANCE_IDS\n"
                # Get private IPs of healthy and InService instances
                HEALTHY_INSTANCES_IPS=$(aws ec2 describe-instances \
                    --instance-ids $HEALTHY_INSTANCE_IDS \
                    --query "Reservations[].Instances[].$IP_QUERY" \
                    --output json)
                # Add IPs to upsert variable
                IPS_UPSERT=$HEALTHY_INSTANCES_IPS
                # Parse JSON array to get IPs separated by space
                HEALTHY_INSTANCES_IPS=$(echo $HEALTHY_INSTANCES_IPS | jq -r '.[]' | tr '\n' ' ')
                echo -e "IPs of healthy instances: $HEALTHY_INSTANCES_IPS\n"
            else 
                echo -e "No healthy and InService instances found in ASG, upsert only current instance IP\n"
            fi
        else 
            echo -e "No running instances found for the IPs of record A, upsert only the current instance IP\n"
        fi

    else
        echo -e "No record A found for $RECORD_NAME, create a new record A with the current instance IP\n"
    fi
    IPS_UPSERT=$(echo $IPS_UPSERT | jq --arg ip "$INSTANCE_IP" 'map({Value: .}) | . + [{Value: $ip}]')
    echo -e "IPs to upsert: $IPS_UPSERT\n"
    # Upsert record A with IPs
    CHANGE_BATCH=$(cat <<EOF
    {"Changes":[{"Action": "UPSERT","ResourceRecordSet": {"Name": "$RECORD_NAME","Type": "A","TTL": 60,"ResourceRecords": $IPS_UPSERT}}]}
EOF
    )
    echo -e "CHANGE BATCH: $CHANGE_BATCH\n"
    aws route53 change-resource-record-sets \
        --hosted-zone-id "$ZONE_ID" \
        --change-batch "$CHANGE_BATCH"
}
### PRIVATE DNS ###
echo -e "UPDATE PRIVATE DNS\n"
for i in {0..4}; do
    if [[ $i -eq 0 ]]; then
        echo -e "Creating record...\n"
    fi
    updateDns "$INSTANCE_PRIV_IP" "$PRIV_ZONE_ID" "$PRIVATE_FILTER_NAME" "$PRIVATE_IP_QUERY"
    sleep 2
    RECORD_IPS=$(aws route53 list-resource-record-sets \
    --hosted-zone-id $PRIV_ZONE_ID \
    --query "ResourceRecordSets[?(Name == '$RECORD_NAME') && (Type == 'A')].ResourceRecords" \
    --output text)
    if echo $RECORD_IPS | grep -q $INSTANCE_PRIV_IP; then
        echo -e "Record creation successful\n"
        break
    else
        if [[ $i -eq 4 ]]; then
            echo -e "Record creation failed too many times, aborting\n"
        else
            echo -e "Record creation failed, retrying...\n"
        fi
    fi
done
### PUBLIC DNS ###
echo -e "UPDATE PUBLIC DNS\n"
# Retrieve Hosted Zone ID from SSM Parameter Store
PUBLIC_ZONE_ID=$(aws ssm get-parameter --name $PARAMETER_NAME --query "Parameter.Value" --output text)
echo -e "Public Zone ID: $PUBLIC_ZONE_ID\n"
ACTUAL_ZONE_ID=""
# Find hosted zone ID from domain if not specified
if [[ "$PUBLIC_ZONE_ID" == "None" || "$PUBLIC_ZONE_ID" == "" ]]; then
    echo -e "No hosted zone ID specified, fetching from domain name\n"
    # List all public hosted zones with specified domain
    PUB_HOSTED_ZONES=$(aws route53 list-hosted-zones-by-name \
        --dns-name "$DOMAIN_NAME" \
        --query "HostedZones[?(Name=='$DOMAIN_NAME') && (Config.PrivateZone == \`false\`)].Id" \
        --output json | jq 'map(ltrimstr("/hostedzone/"))')
    ARRAY_LENGTH=$(echo $PUB_HOSTED_ZONES | jq 'length')
    if [[ $ARRAY_LENGTH -eq 0 ]]; then
        echo -e "No hosted zones found with domain ($DOMAIN_NAME), make sure to create one\n"
    elif [[ $ARRAY_LENGTH -eq 1 ]]; then
        ACTUAL_ZONE_ID=$(echo $PUB_HOSTED_ZONES | jq -r '.[0]')
        echo -e "One hosted zone found with domain ($DOMAIN_NAME): $ACTUAL_ZONE_ID\n"
        # Update Zone ID in Parameter Store
        UPDATE_PARAMETER=$(aws ssm put-parameter --name $PARAMETER_NAME --value $ACTUAL_ZONE_ID --type "String" --overwrite)
        echo -e "Zone ID updated in Parameter Store\n"
    else
        # Parse JSON array to get HZ Ids separated by space
        PUB_HOSTED_ZONES_STRING=$(echo $PUB_HOSTED_ZONES | jq -r '.[]' | tr '\n' ' ')
        echo -e "Hosted zones with domain name: $PUB_HOSTED_ZONES_STRING\n"
        # Resolve NS records of domain to check if they match NS records of hosted zone in Route53
        DOMAIN_NS_RECORDS=$(dig +short NS $DOMAIN_NAME)
        # If an error occurred, log error message, otherwhise check if NS records match
        if [[ -z "$DOMAIN_NS_RECORDS" ]]; then
            echo -e "No NS records found for domain $DOMAIN_NAME, check following logs (error occurred or domain does not exist)\n"
            dig NS $DOMAIN_NAME
        else
            # Create sorted json array of NS records
            DOMAIN_NS_RECORDS_SORTED=$(echo $DOMAIN_NS_RECORDS | jq -R 'split(" ") | map(rtrimstr(".")) | sort')
            # Parse JSON array to get domain NS records separated by space
            DOMAIN_NS_RECORDS_STRING=$(echo $DOMAIN_NS_RECORDS_SORTED | jq -r '.[]' | tr '\n' ' ')
            echo -e "NS records of domain $DOMAIN_NAME: $DOMAIN_NS_RECORDS_STRING\n"
            # Iterate over hosted zones to find one with matching NS records
            for hz_id in $PUB_HOSTED_ZONES_STRING; do
                ZONE_NS_RECORDS_SORTED=$(aws route53 get-hosted-zone \
                    --id "$hz_id" \
                    --query "DelegationSet.NameServers" \
                    --output json | jq 'sort')
                # Parse JSON array to get domain NS records separated by space
                ZONE_NS_RECORDS_STRING=$(echo $ZONE_NS_RECORDS_SORTED | jq -r '.[]' | tr '\n' ' ')
                echo -e "Delegation set for Hosted Zone $hz_id: $ZONE_NS_RECORDS_STRING\n"
                if [[ "$DOMAIN_NS_RECORDS_SORTED" == "$ZONE_NS_RECORDS_SORTED" ]]; then
                    ACTUAL_ZONE_ID=$hz_id
                    echo -e "The NS servers of domain $DOMAIN_NAME match NS servers of hosted zone $hz_id\n"
                    # Update Zone ID in Parameter Store
                    UPDATE_PARAMETER=$(aws ssm put-parameter --name $PARAMETER_NAME --value $ACTUAL_ZONE_ID --type "String" --overwrite)
                    echo -e "Zone ID updated in Parameter Store\n"
                    break
                else
                    echo -e "The NS servers of domain $DOMAIN_NAME do not match NS servers of hosted zone $hz_id\n"
                fi
            done
            if [[ -z "$ACTUAL_ZONE_ID" ]]; then
                echo -e "No suitable zone found, fix delegation to correct nameservers for $DOMAIN_NAME\n"
            else
                echo -e "Found actual Zone ID: $ACTUAL_ZONE_ID\n"
            fi
        fi
    fi
else 
    echo -e "Zone ID specified in template: $PUBLIC_ZONE_ID\n"
    ACTUAL_ZONE_ID=$PUBLIC_ZONE_ID
fi
if [[ -z "$ACTUAL_ZONE_ID" ]]; then
    echo -e "No actual Zone ID found, doing nothing\n"
else
    for i in {0..4}; do
        if [[ $i -eq 0 ]]; then
            echo -e "Upserting record...\n"
        fi
        updateDns "$INSTANCE_PUB_IP" "$ACTUAL_ZONE_ID" "$PUBLIC_FILTER_NAME" "$PUBLIC_IP_QUERY"
        sleep 2
        RECORD_IPS=$(aws route53 list-resource-record-sets \
        --hosted-zone-id $ACTUAL_ZONE_ID \
        --query "ResourceRecordSets[?(Name == '$RECORD_NAME') && (Type == 'A')].ResourceRecords" \
        --output text)
        if echo $RECORD_IPS | grep -q $INSTANCE_PUB_IP; then
            echo -e "Record upsert successful\n"
            break
        else
            if [[ $i -eq 4 ]]; then
                echo -e "Record upsert failed too many times, aborting\n"
            else
                echo -e "Record upsert failed, retrying...\n"
            fi
        fi
    done
fi
# Add tag with Init completion
aws ec2 create-tags --resources $INSTANCE_ID --tags Key=Init,Value=Complete