#!/bin/bash

# This script is used to manage the certificates for the traefik reverse proxy
# It uses acme.sh to issue and renew the certificates
# The script is run by CodeBuild, triggered by a Lambda Custom Resource in the service stack
# that override the EVENT variable in the startBuild command (Create or Delete)
# The HOSTNAME and ASG_NAME variables are also passed by the lambda to CodeBuild as an environment variable
# In all the other cases, the script will renew all the certificates, triggered by a CloudWatch Event

# If the acme.sh is not found in EFS, it will be cloned from the official repository
if ! [[ -d /traefik/acme ]]; then
    echo -e "Acme.sh not found\n"
    mkdir -p /traefik/acme
    cd /traefik/acme
    git clone https://github.com/acmesh-official/acme.sh.git acme-repo
    cd /traefik/acme/acme-repo
    ./acme.sh --install --nocron --no-profile --home /traefik/acme
fi

if [[ "$EVENT" == "Create" ]]; then
    /traefik/acme/acme-repo/acme.sh --issue --server letsencrypt --dns dns_aws -d $HOSTNAME --home /traefik/acme
    cat << EOF > /traefik/etc/${HOSTNAME}.yml
tls:
  certificates:
    - certFile: /traefik/acme/${HOSTNAME}_ecc/fullchain.cer
      keyFile: /traefik/acme/${HOSTNAME}_ecc/${HOSTNAME}.key
      stores:
        - default
EOF
    sed -i "s/.*Last loaded.*/# Last loaded: $(date)/" /traefik/etc/traefik.yml
    aws ssm send-command \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["touch /traefik/etc/traefik.yml"]\
        --targets Key=tag:aws:autoscaling:groupName,Values=${ASG_NAME}

elif [[ "$EVENT" == "Delete" ]]; then
    /traefik/acme/acme-repo/acme.sh --revoke --server letsencrypt -d $HOSTNAME --home /traefik/acme
    /traefik/acme/acme-repo/acme.sh --remove -d $HOSTNAME --home /traefik/acme --syslog 7
    rm -rf /traefik/acme/${HOSTNAME}_ecc
    rm -f /traefik/etc/${HOSTNAME}.yml
    sed -i "s/.*Last loaded.*/# Last loaded: $(date)/" /traefik/etc/traefik.yml
    aws ssm send-command \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["touch /traefik/etc/traefik.yml"]\
        --targets Key=tag:aws:autoscaling:groupName,Values=${ASG_NAME}

elif [[ "$EVENT" == "Renew" ]]; then
    /traefik/acme/acme-repo/acme.sh --renew-all --server letsencrypt --home /traefik/acme
    sed -i "s/.*Last loaded.*/# Last loaded: $(date)/" /traefik/etc/traefik.yml
    aws ssm send-command \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["touch /traefik/etc/traefik.yml"]\
        --targets Key=tag:aws:autoscaling:groupName,Values=${ASG_NAME}
else
    echo -e "Invalid event\n"
fi