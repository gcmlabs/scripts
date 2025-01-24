#!/bin/bash

# Update and install packages
dnf update -y
dnf install -y iptables-services sed wget jq tar bind-utils

# Install AWS CLI
# curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
# unzip awscliv2.zip
# ./aws/install

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
ROUTE_OUTPUT=$(aws ec2 describe-route-tables --route-table-ids ${PrivateRouteTable} --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0']" --output json)
echo "ROUTE OUTPUT: $ROUTE_OUTPUT"
echo ""

if [[ "$ROUTE_OUTPUT" == "[]" ]]; then
    aws ec2 create-route --route-table-id ${PrivateRouteTable} --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
    echo "Route created"
    echo ""

elif echo "$ROUTE_OUTPUT" | grep -q "blackhole"; then
    aws ec2 replace-route --route-table-id ${PrivateRouteTable} --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
    echo "Blackhole found. Route replaced"
    echo ""

else
    NAT_INSTANCE_ID=$(echo "$ROUTE_OUTPUT" | jq -r '.[0].InstanceId')
    NAT_INSTANCE_LIFECYCLE_STATE=$(aws autoscaling describe-auto-scaling-instances --instance-ids $NAT_INSTANCE_ID --query "AutoScalingInstances[0].LifecycleState" --output text)
    if ! [[ "$NAT_INSTANCE_LIFECYCLE_STATE" == "InService" ]]; then
        aws ec2 replace-route --route-table-id ${PrivateRouteTable} --destination-cidr-block 0.0.0.0/0 --instance-id ${!INSTANCE_ID}
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
  level: ERROR
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


### PRIVATE DNS RECORDS ###

# Private DNS Variables
PRIV_HZ_ID=${PrivateHostedZone}
PRIV_RECORD_NAME="lb.${AWS::StackName}-${AWS::Region}.${pDomainName}."

# Get instance private IP from metadata
INSTANCE_PRIV_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4 --header "X-aws-ec2-metadata-token: $TOKEN")


# Get only the HEALTHY instances from the ASG
ASG_NAME=${AWS::StackName}-asg
HEALTHY_INSTANCES=$(aws autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names $ASG_NAME \
    --query "AutoScalingGroups[0].Instances[?(HealthStatus=='Healthy') && (LifecycleState=='InService')].InstanceId" \
    --output text)

echo "HEALTHY AND IN SERVICE INSTANCES $HEALTHY_INSTANCES"
echo ""
# Get the private IPs of the HEALTHY instances that have completed the init phase
if [[ -z "$HEALTHY_INSTANCES" || "$HEALTHY_INSTANCES" == "None" ]]; then
    HEALTHY_INSTANCES=""
fi

if [[ -n "$HEALTHY_INSTANCES" ]]; then
    INSTANCES_PRIV_IPS=$(aws ec2 describe-instances \
        --instance-ids $HEALTHY_INSTANCES \
        --query "Reservations[].Instances[?Tags[?Key=='Init' && Value=='Complete']].PrivateIpAddress" \
        --output text)

    echo "Completed Init Instances Private IPs: $INSTANCES_PRIV_IPS"
    echo ""

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
echo ""

aws route53 change-resource-record-sets --hosted-zone-id "$PRIV_HZ_ID" --change-batch "$CHANGE_BATCH_PRIVATE_RECORD"


### PUBLIC DNS RECORDS ###

### Public DNS Variables ###
DOMAIN_NAME=${pDomainName}

# Retrieve hosted zones matching the domain
PUB_HOSTED_ZONES=($(aws route53 list-hosted-zones-by-name \
  --dns-name "$DOMAIN_NAME" \
  --query "HostedZones[?Name=='$DOMAIN_NAME.' && Config.PrivateZone == \`false\`].Id" \
  --output text | sed 's/\/hostedzone\///g'))

echo "Hosted zones found: ${!PUB_HOSTED_ZONES[@]}"
echo ""
PUB_HZ_ID=""

# Check the number of hosted zones found
if [[ ${!#PUB_HOSTED_ZONES[@]} -eq 0 ]]; then
  echo "No hosted zones found for $DOMAIN_NAME, make sure the corresponding public hosted zone exists"
  echo ""

else
  echo "One or more hosted zones found for $DOMAIN_NAME"
  echo ""
  NS_RECORDS=($(dig +short NS "$DOMAIN_NAME"))

  echo "NS records found: ${!NS_RECORDS[@]}"
  echo ""

  for pub_hosted_zone in "${!PUB_HOSTED_ZONES[@]}"; do

    echo "Checking hosted zone $pub_hosted_zone"
    echo ""

    # Retrieve hosted zone's NS records
    ZONE_NS_RECORDS=($(aws route53 get-hosted-zone \
      --id "$pub_hosted_zone" \
      --query "DelegationSet.NameServers" \
      --output text))

    echo "Hosted zone NS records: ${!ZONE_NS_RECORDS[@]}"
    echo ""

    MATCHES_ALL=true
    for ns_record in "${!NS_RECORDS[@]}"; do
      ns_record_without_dot="${!ns_record%.}"
      if ! [[ " ${!ZONE_NS_RECORDS[@]} " =~ " $ns_record_without_dot " ]]; then
        echo "NS record $ns_record_without_dot not found in hosted zone $pub_hosted_zone"
        echo ""
        MATCHES_ALL=false
        break
      fi
      echo "NS record $ns_record_without_dot found in hosted zone $pub_hosted_zone"
      echo ""
    done

    if $MATCHES_ALL; then
      echo "All NS records match for hosted zone $pub_hosted_zone"
      echo ""
      PUB_HZ_ID="$pub_hosted_zone"
      break
    fi
  done
fi

if [[ -z "$PUB_HZ_ID" ]]; then
  echo "No suitable hosted zone found, create one or fix delegation to the correct nameservers"
  echo ""

else
    echo "Effective hosted zone: $PUB_HZ_ID"
    echo ""

    # Public DNS Variables
    PUB_RECORD_NAME="lb.${AWS::StackName}-${AWS::Region}.${pDomainName}."

    # Get instance public IP from metadata
    INSTANCE_PUB_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 --header "X-aws-ec2-metadata-token: $TOKEN")


    # Get only the HEALTHY instances from the ASG
    ASG_NAME=${AWS::StackName}-asg
    HEALTHY_INSTANCES=$(aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names $ASG_NAME \
        --query "AutoScalingGroups[0].Instances[?(HealthStatus=='Healthy') && (LifecycleState=='InService')].InstanceId" \
        --output text)

    echo "HEALTHY AND IN SERVICE INSTANCES $HEALTHY_INSTANCES"
    echo ""

    # Get the public IPs of the HEALTHY instances that have completed the init phase
    if [[ -z "$HEALTHY_INSTANCES" || "$HEALTHY_INSTANCES" == "None" ]]; then
        HEALTHY_INSTANCES=""
    fi

    if [[ -n "$HEALTHY_INSTANCES" ]]; then
        INSTANCES_PUB_IPS=$(aws ec2 describe-instances \
            --instance-ids $HEALTHY_INSTANCES \
            --query "Reservations[].Instances[?Tags[?Key=='Init' && Value=='Complete']].PublicIpAddress" \
            --output text)

        echo "Completed Init Instances Public IPs: $INSTANCES_PUB_IPS"
        echo ""

        if [[ -z "$INSTANCES_PUB_IPS" ]]; then
            INSTANCES_PUB_IPS=""
            PUB_VALUES_JSON=$(jq -n --arg ip "$INSTANCE_PUB_IP" '[{Value: $ip}]')
        else
            PUB_VALUES_JSON=$(echo "$INSTANCES_PUB_IPS" | \
                jq -R --arg ip "$INSTANCE_PUB_IP" 'split("\n") | map(select(. != "" and . != "None")) | map({Value: .}) | . + [{Value: $ip}]')
        fi
    else
        PUB_VALUES_JSON=$(jq -n --arg ip "$INSTANCE_PUB_IP" '[{Value: $ip}]')
    fi

    # UPSERT the private record in Route53
    CHANGE_BATCH_PUBLIC_RECORD=$(cat <<EOF
    {
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": "$PUB_RECORD_NAME",
                    "Type": "A",
                    "TTL": 60,
                    "ResourceRecords": $PUB_VALUES_JSON
                }
            }
        ]
    }
EOF
    )

    echo "PUBLIC CHANGE BATCH $CHANGE_BATCH_PUBLIC_RECORD"
    echo ""

    aws route53 change-resource-record-sets --hosted-zone-id "$PUB_HZ_ID" --change-batch "$CHANGE_BATCH_PUBLIC_RECORD"
fi


# Add tag so that the instance can be evalued as healthy and running
aws ec2 create-tags --resources ${!INSTANCE_ID} --tags Key=Init,Value=Complete