#!/bin/bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
    echo "Usage: $0 <os_image_path> <output_json_base_path> <channel> <build_architecture>"
    echo "Example: $0 disk.raw measure_output.json hardened x86_64"
    echo "Env: NESTED_IMAGES=\"8:/key_oracle_vm_image.qcow2:key_oracle 8:/workload_vm_image.qcow2:workload\""
    exit 1
fi

OS_IMAGE="$1"
OUTPUT_JSON="$2"
CHANNEL="$3"
ARCH="$4"

BASE_OUT="${OUTPUT_JSON%.json}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Verify dependencies proactively
check_dependencies() {
    local missing_cmds=0
    local deps=(cgpt debugfs qemu-img dd tar find)
    if [[ -n "${NESTED_IMAGES:-}" ]]; then
        for cmd in "${deps[@]}"; do
            if ! command -v "$cmd" &>/dev/null; then
                echo "Error: Required utility '$cmd' is not installed." >&2
                missing_cmds=1
            fi
        done
    fi
    return "$missing_cmds"
}

# Helper to run measurements for both algorithms
run_dual_measurements() {
    local target_image="$1"
    local output_base="$2"
    local measure_cmd="/usr/local/bin/measure.sh"
    if [[ ! -x "$measure_cmd" && -f "$(dirname "$0")/measure.sh" ]]; then
        measure_cmd="$(dirname "$0")/measure.sh"
    fi
    "$measure_cmd" "$target_image" "${output_base}_sha256.json" "$CHANNEL" "$ARCH" sha256
    "$measure_cmd" "$target_image" "${output_base}_sha384.json" "$CHANNEL" "$ARCH" sha384
}

# Helper to extract OVMF firmware from ext4 partition layers and compute offline MRTD
extract_and_measure_ovmf() {
    local part_ext4="$1"
    local output_base="$2"

    local ovmf_tmp="$TMP_DIR/ovmf"
    mkdir -p "$ovmf_tmp"

    local out_fd_file="$ovmf_tmp/OVMF.fd"

    # 1. Attempt exact path extraction based on host-acos directory layout (/tdx-qemu-app/usr/share/ovmf/OVMF.inteltdx.fd)
    debugfs -R "dump /tdx-qemu-app/usr/share/ovmf/OVMF.inteltdx.fd $out_fd_file" "$part_ext4" 2>/dev/null || true

    # 2. If directory path not found, attempt extraction from legacy tarball layout (/tdx-qemu-app.tar)
    if [[ ! -f "$out_fd_file" || ! -s "$out_fd_file" ]]; then
        debugfs -R "dump /tdx-qemu-app.tar $ovmf_tmp/tdx-qemu-app.tar" "$part_ext4" 2>/dev/null || true
        if [[ -f "$ovmf_tmp/tdx-qemu-app.tar" && -s "$ovmf_tmp/tdx-qemu-app.tar" ]]; then
            tar -xf "$ovmf_tmp/tdx-qemu-app.tar" -O usr/share/ovmf/OVMF.inteltdx.fd > "$out_fd_file" 2>/dev/null || \
            tar -xf "$ovmf_tmp/tdx-qemu-app.tar" -O /usr/share/ovmf/OVMF.inteltdx.fd > "$out_fd_file" 2>/dev/null || true
        fi
    fi

    if [[ -f "$out_fd_file" && -s "$out_fd_file" ]]; then
        echo "Calculating OVMF MRTD (using $out_fd_file)..."
        local extract_cmd="/usr/local/bin/extract_image_ovmf"
        if [[ ! -x "$extract_cmd" && -f "$(dirname "$0")/extract_image_ovmf" ]]; then
            extract_cmd="$(dirname "$0")/extract_image_ovmf"
        fi
        local mrtd_hex
        mrtd_hex=$("$extract_cmd" "$out_fd_file" | sed -n 's/^MRTD: //p')

        if [[ -n "$mrtd_hex" ]]; then
            jq -n --arg mrtd "$mrtd_hex" '{mrtd: $mrtd}' > "${output_base}_mrtd.json"
        fi
    else
        echo "Error: Expected active OVMF firmware (/tdx-qemu-app/usr/share/ovmf/OVMF.inteltdx.fd) not found in partition." >&2
        rm -f "$out_fd_file"
        exit 1
    fi
}

if ! check_dependencies; then
    echo "Please install the missing dependencies and try again." >&2
    exit 1
fi

# 1. Run Host OS measurements for both algorithms
echo "Measuring Host OS ($CHANNEL)..."
run_dual_measurements "$OS_IMAGE" "${BASE_OUT}"

# 2. Extract and measure nested images if NESTED_IMAGES env var is provided
if [[ -n "${NESTED_IMAGES:-}" ]]; then
    for nested in $NESTED_IMAGES; do
        PART_NUM=$(echo "$nested" | cut -d':' -f1)
        IMG_PATH=$(echo "$nested" | cut -d':' -f2)
        SUFFIX=$(echo "$nested" | cut -d':' -f3)

        echo "Extracting $IMG_PATH from partition $PART_NUM..."
        
        # Get partition bounds and validate
        if ! SKIP_SECTORS=$(cgpt show -i "$PART_NUM" -b -n "$OS_IMAGE" | tr -d ' ' 2>/dev/null) || \
           ! SIZE_SECTORS=$(cgpt show -i "$PART_NUM" -s -n "$OS_IMAGE" | tr -d ' ' 2>/dev/null) || \
           [[ -z "$SIZE_SECTORS" ]] || [[ "$SIZE_SECTORS" -eq 0 ]]; then
            echo "Error: Partition $PART_NUM not found or empty." >&2
            exit 1
        fi

        if ! [[ "$SKIP_SECTORS" =~ ^[0-9]+$ ]] || ! [[ "$SIZE_SECTORS" =~ ^[0-9]+$ ]]; then
            echo "Error: Invalid numeric partition bounds for $PART_NUM (skip='$SKIP_SECTORS', size='$SIZE_SECTORS')." >&2
            exit 1
        fi
        
        PART_EXT4="$TMP_DIR/part${PART_NUM}.ext4"
        QCOW_FILE="$TMP_DIR/${SUFFIX}.qcow2"
        RAW_FILE="$TMP_DIR/${SUFFIX}.raw"

        # Calculate bytes for skip_bytes dd optimization
        SKIP_BYTES=$((SKIP_SECTORS * 512))
        COUNT_BYTES=$((SIZE_SECTORS * 512))

        # Extract just the partition
        dd if="$OS_IMAGE" of="$PART_EXT4" skip="$SKIP_BYTES" count="$COUNT_BYTES" iflag=skip_bytes,count_bytes bs=4M status=none 2>/dev/null || \
        dd if="$OS_IMAGE" of="$PART_EXT4" skip="$SKIP_SECTORS" count="$SIZE_SECTORS" bs=512 status=none

        # Extract OVMF and measure MRTD once from partition layer if not already measured
        if [[ ! -f "${BASE_OUT}_mrtd.json" ]]; then
            extract_and_measure_ovmf "$PART_EXT4" "${BASE_OUT}"
        fi

        # Extract the nested image from the ext4 partition, capture debugfs errors
        debugfs_err="$TMP_DIR/debugfs_${SUFFIX}.err"
        if ! debugfs -R "dump $IMG_PATH $QCOW_FILE" "$PART_EXT4" 2>"$debugfs_err"; then
            echo "Error: debugfs failed to extract $IMG_PATH:" >&2
            cat "$debugfs_err" >&2
            exit 1
        fi

        if [[ -f "$QCOW_FILE" && -s "$QCOW_FILE" ]]; then
            echo "Converting $IMG_PATH to raw format..."
            qemu-img convert -f qcow2 -O raw "$QCOW_FILE" "$RAW_FILE"

            echo "Measuring nested image: $SUFFIX ($CHANNEL)"
            run_dual_measurements "$RAW_FILE" "${BASE_OUT}_${SUFFIX}"
        else
            echo "Error: $IMG_PATH not extracted or is empty in partition $PART_NUM" >&2
            exit 1
        fi
    done
fi

echo "Composite measurement complete."
