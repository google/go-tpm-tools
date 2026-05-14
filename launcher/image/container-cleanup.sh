#!/bin/bash
echo "Container cleanup script started"

SHUTDOWN_TIMEOUT_SEC=15

# Send SIGTERM to all running workloads so that they can shutdown gracefully.
for ns in $(ctr ns ls -q); do
    tasks=$(ctr -n "$ns" task ls -q)

    if [ -n "$tasks" ]; then
        # Send SIGTERM and move on. No waiting, no killing, no deleting.
        # A workload may decide to ignore or not handle SIGTERM.
        ctr -n "$ns" tasks kill --signal SIGTERM $tasks >/dev/null 2>&1
        echo "SIGTERM sent to $tasks in namespace $ns."
    fi
done

echo "Waiting up to $SHUTDOWN_TIMEOUT_SEC seconds for workloads to shutdown..."

start_time=$(date +%s)
while true; do
    all_empty=true
    for ns in $(ctr ns ls -q); do
        tasks=$(ctr -n "$ns" task ls -q)
        if [ -n "$tasks" ]; then
            all_empty=false
            break
        fi
    done

    if [ "$all_empty" = true ]; then
        echo "All workloads have shutdown gracefully."
        break
    fi

    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    if [ $elapsed -ge $SHUTDOWN_TIMEOUT_SEC ]; then
        echo "Timeout reached; unended tasks will be killed."
        break
    fi

    sleep 1
done
