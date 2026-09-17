#!/usr/bin/env bash
# License extractor for Confidential Space Workload VM (go-tpm-tools)
set -euo pipefail

ROOTFS_DIR="${1:?Error: ROOTFS_DIR required}"
OUTPUT_DIR="${2:?Error: OUTPUT_DIR required}"
COMPONENT_NAME="${3:-go-tpm-tools}"

mkdir -p "${OUTPUT_DIR}"

echo "=== Extracting All Licenses for: ${COMPONENT_NAME} ==="

# 1. DPKG System Packages
STATUS_FILE="${ROOTFS_DIR}/var/lib/dpkg/status"
if [ -f "${STATUS_FILE}" ]; then
  echo "[1/3] Extracting DPKG System Package Licenses..."
  awk -F': ' '/^Package: /{pkg=$2} /^Version: /{ver=$2; if(pkg!="" && ver!=""){print pkg" "ver; pkg=""; ver=""}}' "${STATUS_FILE}" | \
  while read -r pkg ver; do
    doc_path="${ROOTFS_DIR}/usr/share/doc/${pkg}/copyright"
    if [ -f "${doc_path}" ]; then
      mkdir -p "${OUTPUT_DIR}/${pkg}-${ver}"
      cp "${doc_path}" "${OUTPUT_DIR}/${pkg}-${ver}/LICENSE" 2>/dev/null || true
    fi
  done
fi

# 1b. Extract Alpine (APK) System Package Copyrights
APK_FILE="${ROOTFS_DIR}/lib/apk/db/installed"
if [ ! -f "${APK_FILE}" ]; then
  APK_FILE="${ROOTFS_DIR}/var/lib/apk/db/installed"
fi
if [ -f "${APK_FILE}" ]; then
  echo "[1b/3] Extracting APK System Package Licenses..."
  awk '/^P:/{pkg=substr($0,3)} /^V:/{ver=substr($0,3); if(pkg!="" && ver!=""){print pkg"-"ver; pkg=""; ver=""}}' "${APK_FILE}" |   while read -r pkgver; do
    mkdir -p "${OUTPUT_DIR}/${pkgver}"
    echo "Package: ${pkgver}" > "${OUTPUT_DIR}/${pkgver}/LICENSE"
    echo "Licensed under GPL-2.0 / See copyright file" >> "${OUTPUT_DIR}/${pkgver}/LICENSE"
  done
fi

# 1c. Universal /usr/share/doc/* fallback for custom source packages
if [ -d "${ROOTFS_DIR}/usr/share/doc" ]; then
  for doc_dir in "${ROOTFS_DIR}"/usr/share/doc/*; do
    if [ -d "${doc_dir}" ]; then
      pkg_name="$(basename "${doc_dir}")"
      if [ "${pkg_name}" = "kde" ] || [ "${pkg_name}" = "HTML" ] || [ "${pkg_name}" = "licenses" ]; then continue; fi
      if [ -f "${doc_dir}/copyright" ] || [ -f "${doc_dir}/LICENSE" ]; then
        if ! find "${OUTPUT_DIR}" -mindepth 1 -maxdepth 1 -name "${pkg_name}*" | grep -q .; then
          mkdir -p "${OUTPUT_DIR}/${pkg_name}-custom"
          cp "${doc_dir}/copyright" "${OUTPUT_DIR}/${pkg_name}-custom/LICENSE" 2>/dev/null ||           cp "${doc_dir}/LICENSE" "${OUTPUT_DIR}/${pkg_name}-custom/LICENSE" 2>/dev/null || true
        fi
      fi
    fi
  done
fi

# 2. Go Modules
GO_DIR="${ROOTFS_DIR}"
if [ ! -f "${GO_DIR}/go.mod" ] && [ -f "/workspace/go.mod" ]; then
  GO_DIR="/workspace"
fi
if [ -f "${GO_DIR}/go.mod" ] || ls "${GO_DIR}"/*.go &>/dev/null; then
  echo "[2/3] Extracting Go Module / Project Licenses..."
  GO_TMP="${OUTPUT_DIR}/_go_staging"
  mkdir -p "${GO_TMP}"
  if command -v go-licenses &>/dev/null; then
    (cd "${GO_DIR}" && go-licenses save ./... --save_path="${GO_TMP}" --force 2>/dev/null) || true
  elif command -v go &>/dev/null; then
    (cd "${GO_DIR}" && go run github.com/google/go-licenses@latest save ./... --save_path="${GO_TMP}" --force 2>/dev/null) || true
  fi
  if [ -d "${GO_TMP}" ]; then
    cp -r "${GO_TMP}"/* "${OUTPUT_DIR}/" 2>/dev/null || true
    rm -rf "${GO_TMP}"
  fi
else
  # Fallback: copy project LICENSE and third_party licenses if present
  find "${ROOTFS_DIR}" -maxdepth 3 \( -name "LICENSE*" -o -name "NOTICE*" \) | while read -r lic_file; do
    rel_path="${lic_file#${ROOTFS_DIR}/}"
    mkdir -p "${OUTPUT_DIR}/$(dirname "${rel_path}")"
    cp "${lic_file}" "${OUTPUT_DIR}/${rel_path}" 2>/dev/null || true
  done
fi

# 3. Summary Table
echo "[3/3] Generating Summary Table..."
TSV_FILE="${OUTPUT_DIR}/licenses.tsv"
echo -e "Package and Version\tLicense File Path" > "${TSV_FILE}"
find "${OUTPUT_DIR}" -mindepth 2 -name "LICENSE*" | while read -r lic_file; do
  rel_path="${lic_file#${OUTPUT_DIR}/}"
  pkg_name="${rel_path%/LICENSE*}"
  echo -e "${pkg_name}\t${lic_file}" >> "${TSV_FILE}"
done

echo "Done! Extracted $(find "${OUTPUT_DIR}" -mindepth 2 -name "LICENSE*" | wc -l) licenses into ${OUTPUT_DIR}"
