#!/bin/bash

# Monitor network interface operational state changes.
# When an interface transitions to UP state, dynamically trigger its
# runtime optimization via a transient systemd service unit.
ip monitor link | grep --line-buffered -E 'eth[01]:.*state UP' | while read -r event; do
  if [[ "$event" =~ eth0 ]]; then
    intf="eth0"
  elif [[ "$event" =~ eth1 ]]; then
    intf="eth1"
  else
    continue
  fi

  echo "Interface ${intf} state UP event detected: $event" > /dev/console
  /usr/bin/systemd-run --no-block --unit="bc-net-opt-${intf}" /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh "${intf}"
done
