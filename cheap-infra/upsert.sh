#!/bin/bash
PUB_PRIV_RECORD_NAME="jack.sandbox.soluzionifutura.it"
INSTANCE_PRIV_IP="10.10.10.10"
PRIVATE_IPS_UPSERT="[]"
PRIVATE_IPS_UPSERT=$(echo $PRIVATE_IPS_UPSERT | jq --arg ip "$INSTANCE_PRIV_IP" 'map({Value: .}) | . + [{Value: $ip}]')
PRIV_ZONE_ID="Z056703232KBLB4HWOU2"

echo -e "Private IPs to upsert: $PRIVATE_IPS_UPSERT\n"
upsertRecord () {
    CHANGE_BATCH=$(cat <<EOF
    {"Changes":[{"Action": "UPSERT","ResourceRecordSet": {"Name": "$PUB_PRIV_RECORD_NAME","Type": "A","TTL": 60,"ResourceRecords": $1}}]}
EOF
    )
    echo -e "CHANGE BATCH: $CHANGE_BATCH\n"
    aws route53 change-resource-record-sets \
        --hosted-zone-id "$2" \
        --change-batch "$CHANGE_BATCH"
}
upsertRecord "$PRIVATE_IPS_UPSERT" "$PRIV_ZONE_ID"
