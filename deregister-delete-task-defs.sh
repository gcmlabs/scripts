#!/bin/bash

export AWS_PROFILE="sandbox"
export AWS_REGION="eu-west-1"
task_definitions=($(aws ecs list-task-definitions --query "taskDefinitionArns[]" --output text))


for task_def in "${task_definitions[@]}"; do
    echo "Deregistering $task_def..."
    aws ecs deregister-task-definition --task-definition "$task_def" --no-cli-pager
    if [ $? -eq 0 ]; then
        echo "Successfully deregistered $task_def"
    else
        echo "Failed to deregister $task_def"
    fi
done



#!/bin/bash

export AWS_PROFILE="sandbox"
export AWS_REGION="eu-west-1"
task_definitions=($(aws ecs list-task-definitions --status INACTIVE --query "taskDefinitionArns[]" --output text))


for task_def in "${task_definitions[@]}"; do
    echo "Deleting $task_def..."
    aws ecs delete-task-definitions --task-definition "$task_def" --no-cli-pager
    if [ $? -eq 0 ]; then
        echo "Successfully deleted $task_def"
    else
        echo "Failed to delete $task_def"
    fi
done