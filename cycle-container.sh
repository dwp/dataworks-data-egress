#! /bin/sh

# shellcheck disable=SC2039

main() {
  local -r task_definition=${1:?Usage: ${FUNCNAME[0]} $(args)}

  if stop_service; then
    echo Container stopped, starting container.
    start_service "$task_definition"
  else
    echo Failed to shut down web server
    return 1
  fi
}

stop_service() {

  aws --profile dataworks-development --no-paginate ecs update-service --cluster data-egress \
    --service data-egress \
    --force-new-deployment \
    --desired-count 0 &> /dev/null

  timeout 10m bash <<EOF
    while [[ \$(running_count) -gt 0 ]]; do
        echo Waiting for container count to reach 0.
        sleep 10
    done
EOF

}

start_service() {
  local -r task_definition=${1:?Usage: ${FUNCNAME[0]} $(args)}

  aws --profile dataworks-development --no-paginate \
    ecs update-service \
    --cluster data-egress \
    --service data-egress --task-definition "$task_definition" \
    --desired-count 1  &> /dev/null

  timeout 10m bash <<EOF
    while [[ \$(running_count) -eq 0 ]]; do
        echo Waiting for container count to exceed 0.
        sleep 10
    done
EOF
}

running_count() {
  aws --profile dataworks-development ecs describe-services --cluster data-egress \
    --services data-egress | jq -r '.services[0].runningCount'
}

export -f running_count

args() {
  echo task-definition
}

main "$1"
