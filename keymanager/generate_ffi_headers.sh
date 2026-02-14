#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CBINDGEN_BIN="${CBINDGEN_BIN:-cbindgen}"

"${CBINDGEN_BIN}" --quiet \
  "${ROOT_DIR}/km_common" \
  --crate km_common \
  --config "${ROOT_DIR}/km_common/cbindgen.toml" \
  --output "${ROOT_DIR}/km_common/include/km_algorithms.h"

"${CBINDGEN_BIN}" --quiet \
  "${ROOT_DIR}/workload_service/key_custody_core" \
  --crate ws_key_custody_core \
  --config "${ROOT_DIR}/workload_service/key_custody_core/cbindgen.toml" \
  --output "${ROOT_DIR}/workload_service/key_custody_core/include/ws_key_custody_core.h"

"${CBINDGEN_BIN}" --quiet \
  "${ROOT_DIR}/key_protection_service/key_custody_core" \
  --crate kps_key_custody_core \
  --config "${ROOT_DIR}/key_protection_service/key_custody_core/cbindgen.toml" \
  --output "${ROOT_DIR}/key_protection_service/key_custody_core/include/kps_key_custody_core.h"
