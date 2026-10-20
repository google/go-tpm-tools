#!/bin/bash
# pick_zone.sh <machine-type> <comma-separated zones> [<gpu-type> <gpu-count>]
# 
# Query the GCE capacity advisor once per region to find which candidate zone
# is most likely to have Spot capacity for the machine type and optional accelerator.
# Print the zone with the highest obtainability score.
# Candidate zones must be passed in because the advisor does not know which
# zones support confidential VMs.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 4 ]; then
  echo "Usage: $0 <machine-type> <comma-separated zones> [<gpu-type> <gpu-count>]" >&2
  exit 1
fi
machine_type=$1
IFS=',' read -ra zones <<< "$2"
gpu_type=${3:-}
gpu_count=${4:-}

regions=()
declare -A region_zones
for zone in "${zones[@]}"; do
  region=${zone%-*}
  if [ -z "${region_zones[$region]:-}" ]; then
    regions+=("$region")
    region_zones[$region]=$zone
  else
    region_zones[$region]+=",$zone"
  fi
done

best_zone=''
best_score=-1
for region in "${regions[@]}"; do
  score=''
  zone=''
  selection_args=(--instance-selection-machine-types="$machine_type")
  if [ -n "$gpu_type" ] && [ -n "$gpu_count" ]; then
    selection_args=(--instance-selection="name=vm-selection,machine-type=$machine_type,accelerator-type=$gpu_type,accelerator-count=$gpu_count")
  fi
  read -r score zone < <(gcloud beta compute advice capacity \
    --region="$region" \
    --zones="${region_zones[$region]}" \
    --provisioning-model=SPOT \
    "${selection_args[@]}" \
    --target-distribution-shape=ANY_SINGLE_ZONE \
    --size=1 \
    --flatten=recommendations \
    --format='value(recommendations.scores.obtainability,recommendations.shards[0].zone.basename())') || true
  echo "${region}: zone=${zone:-none} obtainability=${score:-none}" >&2
  if [ -n "$zone" ] && awk -v a="$score" -v b="$best_score" 'BEGIN { exit !(a > b) }'; then
    best_score=$score
    best_zone=$zone
  fi
done

if [ -z "$best_zone" ]; then
  echo "No zone found for ${machine_type} in $2" >&2
  exit 1
fi
echo "$best_zone"
