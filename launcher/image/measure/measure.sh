#!/bin/bash

# This script calculates measured boot hashes for a given OS image.
# It extracts boot components from partition 12, computes their hashes,
# and outputs the results to a JSON file.

set -euo pipefail

# --- Global Variables ---
# These are set by setup_temp_dir().
declare TMP_DIR_NAME
declare P12_FILE
declare VMLINUZ_A_FILE VMLINUZ_B_FILE
declare GRUB_CFG_FILE
declare BOOT_EFI_FILE GRUB_EFI_FILE
declare SHIM_SIG_FILE GRUB_SIG_FILE


# --- Core Functions ---

##
# Cleans up the temporary directory on exit.
#
cleanup() {
    if [[ -n "${TMP_DIR_NAME:-}" && -d "$TMP_DIR_NAME" ]]; then
        echo "Cleaning up temporary directory '$TMP_DIR_NAME'..."
        rm -rf "$TMP_DIR_NAME"
    fi
}

##
# Verifies that all required command-line utilities are installed.
#
check_dependencies() {
    echo "Checking for required command-line utilities..."
    local missing_cmds=0
    for cmd in cgpt dd mcopy sha256sum sbattach openssl jq awk grep printf dirname mkdir; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "Error: Required command '$cmd' is not installed." >&2
            missing_cmds=1
        fi
    done
    if [ "$missing_cmds" -eq 1 ]; then
        echo "Please install the missing commands and try again." >&2
        return 1
    fi
}

##
# Creates a temporary directory and defines global paths for extracted files.
#
setup_temp_dir() {
    TMP_DIR_NAME="$(mktemp -d)"
    echo "Created temporary directory: '$TMP_DIR_NAME'..."

    # Define file paths within the temporary directory
    P12_FILE="$TMP_DIR_NAME/p12"
    VMLINUZ_A_FILE="$TMP_DIR_NAME/vmlinuz.A"
    VMLINUZ_B_FILE="$TMP_DIR_NAME/vmlinuz.B"
    GRUB_CFG_FILE="$TMP_DIR_NAME/grub.cfg"
    BOOT_EFI_FILE="$TMP_DIR_NAME/boot.efi"
    GRUB_EFI_FILE="$TMP_DIR_NAME/grub-lakitu.efi"
    SHIM_SIG_FILE="$TMP_DIR_NAME/shim_out.sig"
    GRUB_SIG_FILE="$TMP_DIR_NAME/grub_out.sig"
}

##
# Extracts partition 12 from the OS image using cgpt and dd.
# @param $1: Path to the OS image.
#
extract_partition_12() {
    local os_image_path="$1"
    echo "Extracting partition 12 from '$os_image_path'..."

    local skip_sectors size_sectors
    skip_sectors=$(cgpt show -i 12 -b -n "$os_image_path")
    size_sectors=$(cgpt show -i 12 -s -n "$os_image_path")

    if ! [[ "$skip_sectors" =~ ^[0-9]+$ ]] || ! [[ "$size_sectors" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to get valid numeric skip/size sectors for partition 12." >&2
        cgpt show -i 12 "$os_image_path" >&2
        return 1
    fi

    echo "Partition 12 details: skip=$skip_sectors sectors, size=$size_sectors sectors."
    dd if="$os_image_path" of="$P12_FILE" skip="$skip_sectors" count="$size_sectors" bs=512
    echo "Partition 12 copied to '$P12_FILE'."
}

##
# Copies boot-related files from the extracted partition image using mcopy.
#
extract_boot_components() {
    local arch="$1"
    local shim_path=""

    if [ "$arch" == "x86_64" ]; then
        shim_path="::/efi/boot/bootx64.efi"
    elif [ "$arch" == "aarch64" ]; then
        shim_path="::/efi/boot/bootaa64.efi"
    else
        echo "Error: Unknown arch '$arch'."
        return 1
    fi

    echo "Copying files from partition image '$P12_FILE'..."

    declare -A files_to_copy=(
        ["::/syslinux/vmlinuz.A"]="$VMLINUZ_A_FILE"
        ["::/efi/boot/grub.cfg"]="$GRUB_CFG_FILE"
        ["$shim_path"]="$BOOT_EFI_FILE"
        ["::/efi/boot/grub-lakitu.efi"]="$GRUB_EFI_FILE"
    )

    # vmlinuz.B file exists on amd64 but not on arm64
    if [ "$arch" == "x86_64" ]; then
        files_to_copy["::/syslinux/vmlinuz.B"]="$VMLINUZ_B_FILE"
    fi

    for src in "${!files_to_copy[@]}"; do
        local dest="${files_to_copy[$src]}"
        echo "Copying '$src' to '$dest'..."
        if ! mcopy -i "$P12_FILE" "$src" "$dest"; then
            echo "Error: Failed to mcopy '$src' from '$P12_FILE'."
            return 1
        fi
    done
    echo "All boot components copied successfully."
}

# --- Hash Calculation Functions ---

##
# Computes the SHA256 hash of a given file.
# @param $1: Path to the file to hash.
# @return The SHA256 hash string to stdout.
#
compute_file_hash() {
    sha256sum "$1" | awk '{print $1}'
}

##
# Computes the shell-interpreted kernel command line from grub.cfg.
# @param $1: Path to grub.cfg.
# @param $2: Image identifier ('A' or 'B').
# @return The shell-interpreted command line to stdout.
#
compute_cmdline() {
    local grub_cfg="$1"
    local image_id="$2"
    
    local cmdline_string result=()
    cmdline_string=$(grep "verified image $image_id" -A 1 "$grub_cfg" | tail -n 1)

    # This logic correctly re-assembles the command line, handling quoted arguments.
    eval set -- $cmdline_string
    shift # Remove 'linux' command
    for arg in "$@"; do
        if [[ "$arg" = *[[:space:]]* ]]; then
            result+=('"'"$arg"'"')
        else
            result+=("$arg")
        fi
    done
    
    printf '%s' "$(echo "${result[@]}")"
}

##
# Computes the SHA256 hash of a kernel command line from grub.cfg.
# @param $1: Path to grub.cfg.
# @param $2: Image identifier ('A' or 'B').
# @return The SHA256 hash of the command line to stdout.
#
compute_cmdline_hash() {
    compute_cmdline $1 $2 | sha256sum | awk '{print $1}'
}

##
# Computes the hash of a signed EFI binary by detaching its signature.
# @param $1: Path to the signed EFI file (e.g., bootx64.efi).
# @param $2: Path to store the detached signature.
# @return The hash string to stdout.
#
compute_efi_hash() {
    local efi_file="$1"
    local sig_file="$2"

    if ! sbattach --detach "$sig_file" "$efi_file"; then
        echo "Error: sbattach --detach failed for '$efi_file'." >&2
        return 1
    fi
    
    local efi_hash
    efi_hash=$(openssl pkcs7 -in "$sig_file" -inform der -print | grep "HEX DUMP" | awk -F'HEX DUMP]:' '{print $2}' | awk '{$1=$1;print}')
    
    if [[ -z "$efi_hash" ]]; then
        echo "Error: Extracted EFI hash is empty for '$efi_file'." >&2
        return 1
    fi
    echo "$efi_hash"
}

##
# Writes the collected hashes to a final JSON file.
# @param $1: Output JSON file path.
# @param $2: Channel name.
# @param $3-${10}: The six required hashes.
#
write_json_output() {
    echo "Writing data to JSON file: '$output_json_file'..."
    local output_dir
    output_dir=$(dirname "$output_json_file")

    if [[ ! -d "$output_dir" ]]; then
        echo "Error: Output directory '$output_dir' does not exist." >&2
        return 1
    fi

	jq -n \
		--arg chan "$2" \
		--arg shim "$3" \
		--arg grub "$4" \
		--arg vml_a "$5" \
		--arg vml_b "$6" \
		--arg cmd_a_h "$7" \
		--arg cmd_b_h "$8" \
		--arg cmd_a "$9" \
		--arg cmd_b "${10}" \
		'{
			channel: $chan,
			shim: $shim,
			grub: $grub,
			vmlinuz_a: $vml_a,
			vmlinuz_b: $vml_b,
			kernel_cmdline_a_hash: $cmd_a_h,
			kernel_cmdline_b_hash: $cmd_b_h,
			kernel_cmdline_a: $cmd_a,
			kernel_cmdline_b: $cmd_b
		}' > "$output_json_file"

		if [[ $? -ne 0 || ! -s "$output_json_file" ]]; then
			echo "Error: Failed to create or write to output JSON file '$output_json_file'." >&2
			return 1
		fi
}

# --- Main Logic ---

main() {
    # 1. Parameter Handling & Initial Checks
    if [[ "$#" -ne 4 ]]; then
        echo "Usage: $0 <os_image_path> <output_json_file> <channel> <build_architecture>"
        echo "Example: $0 /path/to/image.bin /path/to/output.json stable x86_64"
        return 1
    fi
    local os_image_path="$1"
    local output_json_file="$2"
    local channel="$3"
    local arch="$4"

    if [[ ! -f "$os_image_path" ]]; then
        echo "Error: OS image path '$os_image_path' not found."
        return 1
    fi

    check_dependencies || return 1
    
    # 2. Setup and Extraction
    setup_temp_dir
    extract_partition_12 "$os_image_path" || return 1
    extract_boot_components "$arch" || return 1
    
    # 3. Compute All Hashes
    echo "Computing all required hashes..."
    local vmlinuz_a_hash vmlinuz_b_hash="" kernel_cmdline_a_hash kernel_cmdline_b_hash shim_hash grub_hash

    vmlinuz_a_hash=$(compute_file_hash "$VMLINUZ_A_FILE")
    if [ "$arch" == "x86_64" ]; then
        vmlinuz_b_hash=$(compute_file_hash "$VMLINUZ_B_FILE")
    fi
    kernel_cmdline_a=$(compute_cmdline "$GRUB_CFG_FILE" "A")
    kernel_cmdline_b=$(compute_cmdline "$GRUB_CFG_FILE" "B")
    kernel_cmdline_a_hash=$(compute_cmdline_hash "$GRUB_CFG_FILE" "A")
    kernel_cmdline_b_hash=$(compute_cmdline_hash "$GRUB_CFG_FILE" "B")
    shim_hash=$(compute_efi_hash "$BOOT_EFI_FILE" "$SHIM_SIG_FILE") || return 1
    grub_hash=$(compute_efi_hash "$GRUB_EFI_FILE" "$GRUB_SIG_FILE") || return 1

    echo "Kernel (vmlinuz.A) hash: $vmlinuz_a_hash"
    echo "Kernel (vmlinuz.B) hash: $vmlinuz_b_hash"
    echo "Kernel cmdline (image A): $kernel_cmdline_a"
    echo "Kernel cmdline (image B): $kernel_cmdline_b"
    echo "Kernel cmdline (image A) hash: $kernel_cmdline_a_hash"
    echo "Kernel cmdline (image B) hash: $kernel_cmdline_b_hash"
    echo "bootx64.efi/bootaa64.efi (shim) hash: $shim_hash"
    echo "grub-lakitu.efi (grub) hash: $grub_hash"

    # 4. Final Output with escaped kernel command line strings
    write_json_output "$output_json_file" "$channel" "$shim_hash" "$grub_hash" \
        "$vmlinuz_a_hash" "$vmlinuz_b_hash" "$kernel_cmdline_a_hash" "$kernel_cmdline_b_hash" \
        "$kernel_cmdline_a" "$kernel_cmdline_b" || return 1

    echo "Measured boot hashes successfully written to '$output_json_file'."
}

main "$@"