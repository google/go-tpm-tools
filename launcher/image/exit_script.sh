#!/bin/bash
#
# Handles container-runner.service post-stop reboot and poweroff actions based
# on EXIT_CODE and EXIT_STATUS.

# Flushes container-runner journal entries through Fluent Bit before poweroff.
# Globals:
#   DRAIN_TIMEOUT_SEC
#   FLUENTBIT_DB_DIR
#   SECONDS
drain_fluent_bit() {
  local db_dir="${FLUENTBIT_DB_DIR:-/var/log/google-fluentbit}"
  local timeout_sec="${DRAIN_TIMEOUT_SEC:-10}"

  journalctl --sync >/dev/null 2>&1 || true

  if ! systemctl is-active --quiet fluent-bit.service; then
    return 0
  fi

  local cursor_file=""
  cursor_file="$(mktemp 2>/dev/null)" || true
  if [[ -n "${cursor_file}" ]]; then
    # Match Fluent Bit's _SYSTEMD_UNIT filter to exclude systemd's UNIT= logs.
    journalctl _SYSTEMD_UNIT=container-runner.service -n 1 \
      --cursor-file="${cursor_file}" -o cat --no-pager >/dev/null 2>&1 || true

    if [[ -s "${cursor_file}" ]]; then
      local deadline=$((SECONDS + timeout_sec))
      while (( SECONDS < deadline )); do
        if grep -aFqf "${cursor_file}" \
          "${db_dir}"/container-runner.log.db* 2>/dev/null; then
          break
        fi
        sleep 0.2
      done
    fi
    rm -f "${cursor_file}"
  fi

  # Stop Fluent Bit before poweroff to flush buffered chunks with network up.
  systemctl stop fluent-bit.service >/dev/null 2>&1 || true
}

main() {
  if [[ "${EXIT_CODE:-exited}" != "exited" ]]; then
    return 0
  fi

  case "${EXIT_STATUS}" in
    3)
      # reboot after 2 min
      shutdown --reboot +2
      ;;
    0 | 1 | 2)
      # poweroff after 2 min
      shutdown --poweroff +2
      ;;
    5)
      drain_fluent_bit
      systemctl --no-block poweroff
      ;;
  esac
}

main "$@"
