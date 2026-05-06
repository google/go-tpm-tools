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
declare HASH_ALG
declare HASH_SUM_CMD

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
trap cleanup EXIT

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
    local image_mode="$2"
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
        ["$shim_path"]="$BOOT_EFI_FILE"
    )

    if [ "$image_mode" == "default" ]; then
        files_to_copy["::/syslinux/vmlinuz.A"]="$VMLINUZ_A_FILE"
        files_to_copy["::/efi/boot/grub.cfg"]="$GRUB_CFG_FILE"
        files_to_copy["::/efi/boot/grub-lakitu.efi"]="$GRUB_EFI_FILE"
        # vmlinuz.B file exists on amd64 but not on arm64
        if [ "$arch" == "x86_64" ]; then
            files_to_copy["::/syslinux/vmlinuz.B"]="$VMLINUZ_B_FILE"
        fi
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
    "$HASH_SUM_CMD" "$1" | awk '{print $1}'
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
# Computes the hash of a kernel command line from grub.cfg.
# @param $1: Path to grub.cfg.
# @param $2: Image identifier ('A' or 'B').
# @return The SHA256 hash of the command line to stdout.
#
compute_cmdline_hash() {
    compute_cmdline $1 $2 | "$HASH_SUM_CMD" | awk '{print $1}'
}

##
# Computes the hash of a signed EFI binary by detaching its signature.
# @param $1: Path to the signed EFI file (e.g., bootx64.efi).
# @param $2: Path to store the detached signature.
# @return The hash string to stdout.
#
compute_efi_hash() {
    local efi_file="$1"

    case "$HASH_ALG" in
        sha256) lief_algo="SHA_256" ;;
        sha384) lief_algo="SHA_384" ;;
        *) echo "Error: Unsupported LIEF algorithm '$HASH_ALG'" >&2; return 1 ;;
    esac

    python3 -c "
import lief
import sys

binary = lief.parse('$efi_file')
if not binary:
    sys.exit(1)
digest = binary.authentihash(lief.PE.ALGORITHMS.$lief_algo)
print(''.join(f'{b:02x}' for b in digest))
"
}

##
# Computes the PE/COFF Authenticode hash of an EFI binary by parsing the
# image directly, mirroring sbsigntools' image_pecoff_parse / image_find_regions.
# This function walks the PE headers, skips the CheckSum and Certificate Table
# data-directory entry, hashes sections in section-table order, appends any
# endjunk, and zero-extends the buffer to an 8-byte alignment when required,
# matching the on-disk bytes signed by sbsign.
# @param $1: Path to the EFI file.
# @return The hash string to stdout.
#
compute_efi_authenticode_hash() {
    local efi_file="$1"
    python3 - "$efi_file" "$HASH_ALG" <<'PY'
import hashlib, struct, sys
path, alg = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    d = bytearray(f.read())

def parse_and_find_regions(d):
    # DOS header sanity (mirrors sbsigntools image_pecoff_parse).
    if len(d) < 0x40:
        sys.stderr.write("file is too small for DOS header\n"); sys.exit(1)
    if d[0:2] != b"MZ":
        sys.stderr.write("Invalid DOS header magic\n"); sys.exit(1)

    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    if e_lfanew >= len(d):
        sys.stderr.write("pehdr is beyond end of file [0x%08x]\n" % e_lfanew); sys.exit(1)
    # PE header is nt_signature(4) + COFF file header(20) = 24 bytes.
    if e_lfanew + 24 > len(d):
        sys.stderr.write("File not large enough to contain pehdr\n"); sys.exit(1)
    if d[e_lfanew:e_lfanew+4] != b"PE\0\0":
        sys.stderr.write("Invalid PE header signature\n"); sys.exit(1)

    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", d, coff + 2)[0]
    size_opt = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    if opt + size_opt > len(d):
        sys.stderr.write("file is too small for a.out header\n"); sys.exit(1)
    magic = struct.unpack_from("<H", d, opt)[0]
    if magic not in (0x10b, 0x20b):
        sys.stderr.write("Invalid PE optional header magic 0x%x\n" % magic); sys.exit(1)
    sec_tbl = opt + size_opt
    cksum_off = opt + 64
    certdir = opt + (128 if magic == 0x10b else 144)
    # opthdr must be large enough to contain the cert data directory entry.
    cert_dir_end = (certdir - opt) + 8
    if size_opt < cert_dir_end:
        sys.stderr.write(
            "PE opt header too small (%d bytes) to contain a suitable data directory (need %d bytes)\n"
            % (size_opt, cert_dir_end)); sys.exit(1)
    size_hdrs = struct.unpack_from("<I", d, opt + 60)[0]
    cert_va, cert_table_size = struct.unpack_from("<II", d, certdir)

    # Build the same hash regions sbsigntools' image_find_regions builds, and
    # carry a cumulative byte counter (sbsigntools' `bytes`) the same way.
    regions = []
    # Region 0: begin -> CheckSum
    regions.append((0, cksum_off))
    bytes_total = cksum_off
    bytes_total += 4  # skipped 4-byte CheckSum
    # Region 1: CheckSum+4 -> CertDirEntry
    r1_start, r1_size = cksum_off + 4, certdir - (cksum_off + 4)
    regions.append((r1_start, r1_size))
    bytes_total += r1_size
    bytes_total += 8  # skipped 8-byte cert data-dir entry
    # Region 2: CertDirEntry+8 -> SizeOfHeaders
    r2_start, r2_size = certdir + 8, size_hdrs - (certdir + 8)
    regions.append((r2_start, r2_size))
    bytes_total += r2_size

    # Walk sections in section-table order (matches sbsigntools image_find_regions:
    # the gap-warn fires against the previously-appended section, before the qsort).
    prev_end, prev_name = size_hdrs, "headers"
    for i in range(nsec):
        sh = sec_tbl + i * 40
        name = bytes(d[sh:sh+8]).rstrip(b"\0").decode("ascii", errors="replace")
        sz  = struct.unpack_from("<I", d, sh + 16)[0]
        ptr = struct.unpack_from("<I", d, sh + 20)[0]
        if sz == 0:
            continue
        if ptr != prev_end:
            sys.stderr.write(
                "warning: gap in section table between %s and %s\n" % (prev_name, name))
        regions.append((ptr, sz))
        bytes_total += sz
        prev_end, prev_name = ptr + sz, name

    # Match sbsigntools image_find_regions: qsort all regions by file offset.
    regions.sort()

    # Endjunk: [buf+bytes_total .. size - cert_table_size]. Appended after the
    # sort, mirroring sbsigntools (the endjunk region becomes the last region).
    ej_start = bytes_total
    ej_end = len(d) - cert_table_size
    if ej_end > ej_start:
        regions.append((ej_start, ej_end - ej_start))
        sys.stderr.write(
            "warning: data remaining[%d vs %d]: gaps between PE/COFF sections?\n"
            % (bytes_total + cert_table_size, len(d)))
    elif ej_end < ej_start:
        sys.stderr.write("warning: checksum areas are greater than image size\n")

    # Tianocore multi-sign alignment: data_size = align_up(last_region_end, 8),
    # matching sbsigntools image.c (`align_up((r->data - buf) + r->size, 8)`).
    last_off, last_sz = regions[-1]
    data_size = (last_off + last_sz + 7) & ~7
    return regions, data_size

# Mirror sbsigntools image_load: when data_size > image->size, zero-extend the
# buffer up to data_size and re-run the parse. The pad bytes then fold into
# the endjunk region naturally on the next pass.
while True:
    regions, data_size = parse_and_find_regions(d)
    if data_size > len(d):
        d.extend(b"\0" * (data_size - len(d)))
        continue
    break

h = hashlib.new(alg)
for off, sz in regions:
    h.update(bytes(d[off:off+sz]))
print(h.hexdigest())
PY
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
	    --arg alg "$HASH_ALG" \
		--arg chan "$2" \
		--arg shim "$3" \
		--arg grub "$4" \
		--arg vml_a "$5" \
		--arg vml_b "$6" \
		--arg cmd_a_h "$7" \
		--arg cmd_b_h "$8" \
		--arg cmd_a "$9" \
		--arg cmd_b "${10}" \
		--arg pe_a "${11}" \
		--arg pe_b "${12}" \
		--arg img_type "${13}" \
		--arg uki_efi "${14}" \
		'{
			channel: $chan,
			alg: $alg,
			image_type: $img_type,
			shim: $shim,
			grub: $grub,
			vmlinuz_a: $vml_a,
			vmlinuz_b: $vml_b,
			kernel_cmdline_a_hash: $cmd_a_h,
			kernel_cmdline_b_hash: $cmd_b_h,
			kernel_cmdline_a: $cmd_a,
			kernel_cmdline_b: $cmd_b,
			vmlinuz_a_pe: $pe_a,
			vmlinuz_b_pe: $pe_b,
			uki_efi: $uki_efi
		}' > "$output_json_file"

		if [[ $? -ne 0 || ! -s "$output_json_file" ]]; then
			echo "Error: Failed to create or write to output JSON file '$output_json_file'." >&2
			return 1
		fi
}

# --- Main Logic ---

main() {
    # 1. Parameter Handling & Initial Checks
    if [[ "$#" -lt 5 || "$#" -gt 6 ]]; then
        echo "Usage: $0 <os_image_path> <output_json_file> <channel> <build_architecture> <hash_algo:sha256|sha384> [image_mode:default|uki]"
        echo "Example: $0 /path/to/image.bin /path/to/output.json stable x86_64 sha384"
        echo "Example: $0 /path/to/image.bin /path/to/output.json hardened x86_64 sha384 uki"
        return 1
    fi
    local os_image_path="$1"
    local output_json_file="$2"
    local channel="$3"
    local arch="$4"
    HASH_ALG="$5"
    local image_mode="${6:-default}"

    if [[ ! -f "$os_image_path" ]]; then
        echo "Error: OS image path '$os_image_path' not found."
        return 1
    fi

    case "$HASH_ALG" in
        sha256) HASH_SUM_CMD="sha256sum" ;;
        sha384) HASH_SUM_CMD="sha384sum" ;;
        *) echo "Error: Unsupported hash algorithm '$HASH_ALG'. Use sha256 or sha384."; return 1 ;;
    esac

    case "$image_mode" in
        default|uki) ;;
        *) echo "Error: Unsupported image mode '$image_mode'. Use 'default' or 'uki'."; return 1 ;;
    esac

    check_dependencies || return 1

    # 2. Setup and Extraction
    setup_temp_dir
    extract_partition_12 "$os_image_path" || return 1
    extract_boot_components "$arch" "$image_mode" || return 1

    # 3. Compute All Hashes
    echo "Computing all required hashes using $HASH_ALG (image_mode=$image_mode)..."
    local vmlinuz_a_hash="" vmlinuz_b_hash="" kernel_cmdline_a="" kernel_cmdline_b=""
    local kernel_cmdline_a_hash="" kernel_cmdline_b_hash=""
    local shim_hash="" grub_hash="" vmlinuz_a_pe_hash="" vmlinuz_b_pe_hash=""
    local uki_efi_hash=""

    if [ "$image_mode" == "uki" ]; then
        uki_efi_hash=$(compute_efi_authenticode_hash "$BOOT_EFI_FILE") || return 1
        echo "UKI bootx64.efi/bootaa64.efi hash: $uki_efi_hash"
    else
        vmlinuz_a_hash=$(compute_file_hash "$VMLINUZ_A_FILE")
        vmlinuz_a_pe_hash=$(compute_efi_hash "$VMLINUZ_A_FILE")
        if [ "$arch" == "x86_64" ]; then
            vmlinuz_b_hash=$(compute_file_hash "$VMLINUZ_B_FILE")
            vmlinuz_b_pe_hash=$(compute_efi_hash "$VMLINUZ_B_FILE")
        fi
        kernel_cmdline_a=$(compute_cmdline "$GRUB_CFG_FILE" "A")
        kernel_cmdline_b=$(compute_cmdline "$GRUB_CFG_FILE" "B")
        kernel_cmdline_a_hash=$(compute_cmdline_hash "$GRUB_CFG_FILE" "A")
        kernel_cmdline_b_hash=$(compute_cmdline_hash "$GRUB_CFG_FILE" "B")
        shim_hash=$(compute_efi_hash "$BOOT_EFI_FILE") || return 1
        grub_hash=$(compute_efi_hash "$GRUB_EFI_FILE") || return 1

        echo "Kernel (vmlinuz.A) hash: $vmlinuz_a_hash"
        echo "Kernel (vmlinuz.B) hash: $vmlinuz_b_hash"
        echo "Kernel (vmlinuz.A) PE hash: $vmlinuz_a_pe_hash"
        echo "Kernel (vmlinuz.B) PE hash: $vmlinuz_b_pe_hash"
        echo "Kernel cmdline (image A): $kernel_cmdline_a"
        echo "Kernel cmdline (image B): $kernel_cmdline_b"
        echo "Kernel cmdline (image A) hash: $kernel_cmdline_a_hash"
        echo "Kernel cmdline (image B) hash: $kernel_cmdline_b_hash"
        echo "bootx64.efi/bootaa64.efi (shim) hash: $shim_hash"
        echo "grub-lakitu.efi (grub) hash: $grub_hash"
    fi

    # 4. Final Output with escaped kernel command line strings
    write_json_output "$output_json_file" "$channel" "$shim_hash" "$grub_hash" \
        "$vmlinuz_a_hash" "$vmlinuz_b_hash" "$kernel_cmdline_a_hash" "$kernel_cmdline_b_hash" \
        "$kernel_cmdline_a" "$kernel_cmdline_b" "$vmlinuz_a_pe_hash" "$vmlinuz_b_pe_hash" \
        "$image_mode" "$uki_efi_hash" || return 1

    echo "Measured boot hashes successfully written to '$output_json_file'."
}

main "$@"