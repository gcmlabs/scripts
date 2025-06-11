#!/bin/bash

# Script in the buildspec that enables stickiness and a scheduled rule
# to invoke a lambda after 1 hour to disable stickiness again

SCHEDULED_RULE_NAME="test-jack-stickiness-scheduled-rule"
SCHEDULED_RULE_ARN="arn:aws:events:eu-central-1:861507897222:rule/$SCHEDULED_RULE_NAME"
TARGET_GROUP_ARN="arn:aws:elasticloadbalancing:eu-central-1:861507897222:targetgroup/test-jack/91e8eff8c836fff9"
export AWS_PROFILE="sandbox"

# Enable the stickiness and check if it was successful
STICKINESS_ENABLED=false
while [[ "$STICKINESS_ENABLED" == "false" ]]; do
    STICKINESS_ENABLED=$(aws elbv2 modify-target-group-attributes \
        --target-group-arn "$TARGET_GROUP_ARN" \
        --attributes Key=stickiness.enabled,Value=true Key=stickiness.type,Value=lb_cookie Key=stickiness.lb_cookie.duration_seconds,Value=3600 \
        --query "Attributes[?Key=='stickiness.enabled'].Value" --output text)

    if [[ "$STICKINESS_ENABLED" == "true" ]]; then
        # Tag the scheduled rule with enable timestamp so that the lambda will know when to disable stickiness
        aws events tag-resource \
            --resource-arn "$SCHEDULED_RULE_ARN" \
            --tags Key=EnableTimestamp,Value="$(date +%s)"
        echo -e "Stickiness enabled successfully, proceeding to disable the scheduled rule.\n"
    else
        echo -e "Stickiness not enabled yet, retrying...\n"
    fi
done

# Enable the scheduled rule and check if it was successful
RULE_ENABLED=false
while [[ "$RULE_ENABLED" == "false" ]]; do
    aws events enable-rule \
        --name "$SCHEDULED_RULE_NAME"
    
    RULE_STATE=$(aws events describe-rule \
        --name "$SCHEDULED_RULE_NAME" \
        --query "State" --output text)
    
    if [[ "$RULE_STATE" == "ENABLED" ]]; then
        echo -e "Scheduled rule enabled successfully.\n"
        RULE_ENABLED=true
    else
        echo -e "Scheduled rule not enabled yet, retrying...\n"
    fi
done
