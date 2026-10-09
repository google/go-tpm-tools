#!/bin/bash
# pick_zone.sh <machine-type> <comma-separated zones>
# 
# Query the GCE capacity advisor once per region to find which candidate zone
# is most likely to have Spot capacity for the machine type.
# Print the zone with the highest obtainability score.
# Exit non-zero if no zone scores at least the minimum threshold.
# Candidate zones must be passed in because the advisor does not know which
# zones support confidential VMs.
set -euo pipefail

# For Spot VMs, the advisor returns scores of 0.9, 0.5, 0.1, or 0.0.
# Scores from 0.4 to 0.6 mean moderately likely, while 0.1 means unlikely.
# A threshold of 0.5 accepts 0.5 and rejects 0.1.
# Requiring 0.9 is too strict and rejects zones that usually work.
MIN_OBTAINABILITY=0.5

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
best_score=0
for region in "${regions[@]}"; do
  score=''
  zone=''
  read -r score zone < <(gcloud beta compute advice capacity \
    --region="$region" \
    --zones="${region_zones[$region]}" \
    --provisioning-model=SPOT \
    --instance-selection-machine-types="$machine_type" \
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

if [ -z "$best_zone" ] || awk -v a="$best_score" -v b="$MIN_OBTAINABILITY" 'BEGIN { exit !(a < b) }'; then
  echo "No zone with obtainability >= ${MIN_OBTAINABILITY} for ${machine_type} in $2" >&2
  exit 1
fi
echo "$best_zone"
