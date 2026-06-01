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
    local deps=(cgpt debugfs qemu-img dd)
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
    /usr/local/bin/measure.sh "$target_image" "${output_base}.json" "$CHANNEL" "$ARCH" sha256
    /usr/local/bin/measure.sh "$target_image" "${output_base}_sha384.json" "$CHANNEL" "$ARCH" sha384
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
