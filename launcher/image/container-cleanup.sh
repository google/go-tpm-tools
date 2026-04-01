#!/bin/bash

SHUTDOWN_TIMEOUT_SEC=15

# Send SIGTERM to all running workloads so that they can shutdown gracefully.
for ns in $(ctr ns ls -q); do
    tasks=$(ctr -n "$ns" task ls -q)
    
    if [ -n "$tasks" ]; then
        # Send SIGTERM and move on. No waiting, no killing, no deleting.
        # A workload may decide to ignore or not handle SIGTERM.
        ctr -n "$ns" tasks kill --signal SIGTERM $tasks >/dev/null 2>&1
        echo "SIGTERM sent to $tasks; allowing $SHUTDOWN_TIMEOUT_SEC seconds for graceful shutdown."
        
        # Allow $SHUTDOWN_TIMEOUT_SEC seconds for the workload to shutdown.
        sleep $SHUTDOWN_TIMEOUT_SEC

        echo "Container cleanup exits; unended tasks will be killed."
    fi
done
