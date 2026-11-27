#!/bin/bash
# pick_zone.sh <machine-type> <comma-separated zones>
# 
# Query the GCE capacity advisor once per region to find which candidate zone
# is most likely to have Spot capacity for the machine type.
# Print that zone's region so the caller can use regional bulk create to pick
# an available zone in the region.
# Candidate zones must be passed in because the advisor does not know which
# zones support confidential VMs.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "Usage: $0 <machine-type> <comma-separated zones>" >&2
  exit 1
fi
machine_type=$1
IFS=',' read -ra zones <<< "$2"

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
best_uptime=-1
for region in "${regions[@]}"; do
  score=''
  uptime=''
  zone=''
  read -r score uptime zone < <(gcloud beta compute advice capacity \
    --region="$region" \
    --zones="${region_zones[$region]}" \
    --provisioning-model=SPOT \
    --instance-selection-machine-types="$machine_type" \
    --target-distribution-shape=ANY_SINGLE_ZONE \
    --size=1 \
    --flatten=recommendations \
    --format='value(recommendations.scores.obtainability,recommendations.scores.estimatedUptime,recommendations.shards[0].zone.basename())') || true
  uptime_s=${uptime%s}
  echo "${region}: zone=${zone:-none} obtainability=${score:-none} uptime=${uptime:-none}" >&2
  if [ -n "$zone" ] && awk -v s="$score" -v bs="$best_score" -v u="${uptime_s:-0}" -v bu="$best_uptime" \
    'BEGIN { exit !(s > bs || (s == bs && u > bu)) }'; then
    best_score=$score
    best_uptime=${uptime_s:-0}
    best_zone=$zone
  fi
done

if [ -z "$best_zone" ]; then
  echo "No zone found for ${machine_type} in $2" >&2
  exit 1
fi
echo "${best_zone%-*}"
