#!/bin/bash

# Monitor network interface operational state changes.
# When an interface transitions to UP state, dynamically trigger its
# runtime optimization via a transient systemd service unit.
log_echo() {
  local btime
  btime=$(awk '/btime/{print $2}' /proc/stat 2>/dev/null || echo 0)
  local current
  current=$(date +%s.%N 2>/dev/null || echo 0)
  local ts
  ts=$(awk -v btime="$btime" -v current="$current" 'BEGIN {printf "[%12.6f]", current - btime}' 2>/dev/null || echo "[   0.000000]")
  echo "$ts $*"
}

ip monitor link | grep --line-buffered -E 'eth[01]:.*state UP' | while read -r event; do
  if [[ "$event" =~ eth0 ]]; then
    intf="eth0"
  elif [[ "$event" =~ eth1 ]]; then
    intf="eth1"
  else
    continue
  fi

  log_echo "Interface ${intf} state UP event detected: $event" > /dev/console
  /usr/bin/systemd-run --no-block --unit="bc-net-opt-${intf}" /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh "${intf}"
done
