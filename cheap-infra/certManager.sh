#!/bin/bash

# This script is used to manage the certificates for the traefik reverse proxy
# It uses acme.sh to issue and renew the certificates
# The script is run by CodeBuil, triggered by a Lambda Custom Resource in the service stack
# that override the EVENT variable in the startBuild command (Create or Delete)
# The DOMAIN variable is also passed by the lambda to CodeBuild as an environment variable
# In all the other cases, the script will renew all the certificates, triggered by a CloudWatch Event

# If the acme.sh is not found in EFS, it will be cloned from the official repository
if ! [[ -d /traefik/acme/acme.sh ]]; then
    echo "acme.sh not found"
    cd /traefik/acme
    git clone https://github.com/acmesh-official/acme.sh.git
    cd /traefik/acme/acme.sh
    # Install acme.sh setting home as the specified directory (inside EFS)
    ./acme.sh --install --nocron --home /traefik/acme
    source /root/.bashrc
fi

if [[ "$EVENT" == "Create" ]]; then
    acme.sh --issue --server letsencrypt --dns dns_aws -d $DOMAIN
    cat << EOF > /traefik/etc/${DOMAIN}.yml
tls:
  certificates:
    - certFile: /traefik/acme/.acme.sh/${DOMAIN}_ecc/fullchain.cer
      keyFile: /traefik/acme/.acme.sh/${DOMAIN}_ecc/${DOMAIN}.key
      stores:
        - default
EOF


elif [[ "$EVENT" == "Delete" ]]; then
    acme.sh --revoke --server letsencrypt -d $DOMAIN
    acme.sh --remove -d $DOMAIN
    rm -rf /traefik/acme/.acme.sh/${DOMAIN}_ecc
    rm -rf /traefik/etc/${DOMAIN}.yml
    touch /traefik/etc/traefik.yml
else
    acme.sh --renew-all --server letsencrypt
    touch /traefik/etc/traefik.yml
fi



