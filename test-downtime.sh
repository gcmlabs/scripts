#!/bin/bash

URL="https://polarity.dev"
INTERVAL=2
LOGFILE="/tmp/downtime-test.log"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    {
        echo "[$TIMESTAMP] Response:"
        curl -I -s "$URL"
        echo "-------------------------"
    } >> "$LOGFILE"

    sleep "$INTERVAL"
done
