#!/bin/bash

# This script is used to manage the certificates for the traefik reverse proxy
# It uses acme.sh to issue and renew the certificates
# The script is run by CodeBuild, triggered by a Lambda Custom Resource in the service stack
# that override the EVENT variable in the startBuild command (Create or Delete)
# The DOMAIN and ASG_NAME variables are also passed by the lambda to CodeBuild as an environment variable
# In all the other cases, the script will renew all the certificates, triggered by a CloudWatch Event

# If the acme.sh is not found in EFS, it will be cloned from the official repository
if ! [[ -d /traefik/acme ]]; then
    echo -e "Acme.sh not found\n"
    mkdir -p /traefik/acme
    cd /traefik/acme
    git clone https://github.com/acmesh-official/acme.sh.git acme-repo
    cd /traefik/acme/acme-repo
    ./acme.sh --install --nocron --no-profile --home /traefik/acme --log /traefik/acme/acme.log --syslog 7
fi

if [[ "$EVENT" == "Create" ]]; then
    /traefik/acme/acme-repo/acme.sh --issue --server letsencrypt --dns dns_aws -d $DOMAIN --home /traefik/acme --syslog 7
    cat << EOF > /traefik/etc/${DOMAIN}.yml
tls:
  certificates:
    - certFile: /traefik/acme/${DOMAIN}_ecc/fullchain.cer
      keyFile: /traefik/acme/${DOMAIN}_ecc/${DOMAIN}.key
      stores:
        - default
EOF
    sed -i "s/.*Last loaded.*/# Last loaded: $(date)/" /traefik/etc/traefik.yml
    aws ssm send-command \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["touch /traefik/etc/traefik.yml"]\
        --targets Key=tag:aws:autoscaling:groupName,Values=${ASG_NAME}

elif [[ "$EVENT" == "Delete" ]]; then
    /traefik/acme/acme-repo/acme.sh --revoke --server letsencrypt -d $DOMAIN --home /traefik/acme --syslog 7
    /traefik/acme/acme-repo/acme.sh --remove -d $DOMAIN --home /traefik/acme --syslog 7
    rm -rf /traefik/acme/${DOMAIN}_ecc
    rm -f /traefik/etc/${DOMAIN}.yml
    sed -i "s/.*Last loaded.*/# Last loaded: $(date)/" /traefik/etc/traefik.yml
    aws ssm send-command \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["touch /traefik/etc/traefik.yml"]\
        --targets Key=tag:aws:autoscaling:groupName,Values=${ASG_NAME}

elif [[ "$EVENT" == "Renew" ]]; then
    /traefik/acme/acme-repo/acme.sh --renew-all --server letsencrypt --home /traefik/acme --syslog 7
    sed -i "s/.*Last loaded.*/# Last loaded: $(date)/" /traefik/etc/traefik.yml
    aws ssm send-command \
        --document-name "AWS-RunShellScript" \
        --parameters commands=["touch /traefik/etc/traefik.yml"]\
        --targets Key=tag:aws:autoscaling:groupName,Values=${ASG_NAME}
else
    echo -e "Invalid event\n"
fi