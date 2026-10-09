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
    for cmd in cgpt dd mcopy sha256sum sha384sum sbattach openssl jq awk grep printf dirname mkdir; do
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
# Extracts a file from $P12_FILE using mcopy with a consistent error message.
# @param $1: source path inside the FAT (e.g. '::/efi/boot/bootx64.efi').
# @param $2: destination path on local disk.
#
mcopy_from_p12() {
    local src="$1" dst="$2"
    if ! mcopy -i "$P12_FILE" "$src" "$dst"; then
        echo "Error: Failed to mcopy '$src' from '$P12_FILE'." >&2
        return 1
    fi
}

##
# Detects the image mode by inspecting the boot EFI binary already extracted
# to $BOOT_EFI_FILE by extract_boot_components.
# Uses conservative auto-detection: positive evidence is required on both
# sides, with a hard error on anything unrecognized.
#   .sbat present AND content contains 'https://github.com/rhboot/shim'
#       => 'default' (shim + grub + kernel layout)
#   .setup present (x86/x86_64 cos EFI-stub image), OR
#   arm64 Linux Image magic 'ARM\x64' at offset 0x38 (arm64 cos EFI-stub
#   image, which has only .text and .data sections)
#       => 'uki' (single-blob: bootx64.efi / bootaa64.efi w/ EFI stub)
#   otherwise => hard error, listing sections found.
#
# @return The detected mode ('default' or 'uki') to stdout.
#
detect_image_mode() {
    python3 - "$BOOT_EFI_FILE" <<'PY'
import struct, sys
path = sys.argv[1]
with open(path, "rb") as f:
    d = f.read()

# Walk the PE headers directly with stdlib struct, read the section table from raw bytes.
if len(d) < 0x40 or d[:2] != b"MZ":
    sys.stderr.write("Error: '%s' is not a PE binary (bad DOS header)\n" % path)
    sys.exit(1)
e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
if e_lfanew + 24 > len(d) or d[e_lfanew:e_lfanew+4] != b"PE\0\0":
    sys.stderr.write("Error: '%s' has invalid PE signature\n" % path)
    sys.exit(1)
coff = e_lfanew + 4
nsec = struct.unpack_from("<H", d, coff + 2)[0]
size_opt = struct.unpack_from("<H", d, coff + 16)[0]
sec_tbl = coff + 20 + size_opt
if sec_tbl + nsec * 40 > len(d):
    sys.stderr.write("Error: '%s' has malformed PE section table\n" % path)
    sys.exit(1)

sections = {}  # name -> (ptr, size)
for i in range(nsec):
    sh = sec_tbl + i * 40
    name = bytes(d[sh:sh+8]).rstrip(b"\0").decode("ascii", errors="replace")
    sz  = struct.unpack_from("<I", d, sh + 16)[0]
    ptr = struct.unpack_from("<I", d, sh + 20)[0]
    sections[name] = (ptr, sz)

SHIM_URL = b"https://github.com/rhboot/shim"
if ".sbat" in sections:
    ptr, sz = sections[".sbat"]
    if ptr + sz > len(d):
        sys.stderr.write(
            "Error: '%s' .sbat section extends past EOF\n" % path)
        sys.exit(1)
    if SHIM_URL in bytes(d[ptr:ptr+sz]):
        print("default")
        sys.exit(0)
# arm64 Image header: https://docs.kernel.org/arch/arm64/booting.html
if ".setup" in sections or d[0x38:0x3C] == b"ARM\x64":
    print("uki")
    sys.exit(0)
sys.stderr.write(
    "Error: '%s' did not match any known boot-EFI layout. "
    "Recognized markers: '.sbat' containing %r (shim), '.setup' "
    "(x86 cos EFI-stub), or 'ARM\\x64' at 0x38 (arm64 cos EFI-stub). "
    "Sections found: %s\n"
    % (path, SHIM_URL.decode(), sorted(sections)))
sys.exit(1)
PY
}

##
# Copies boot-related files from the extracted partition image using mcopy.
# The boot EFI (bootx64.efi/bootaa64.efi) is required and is a hard error if
# missing. The default-mode extras (vmlinuz.A/B, grub.cfg, grub-lakitu.efi)
# are best-effort: uki images don't have them, and absence is silently
# skipped here. If a default-mode image is missing one, the downstream
# hashing step will fail when it tries to read the file.
#
# @param $1: build architecture ('x86_64' or 'aarch64').
#
extract_boot_components() {
    local arch="$1"
    local boot_src
    case "$arch" in
        x86_64)   boot_src="::/efi/boot/bootx64.efi" ;;
        aarch64)  boot_src="::/efi/boot/bootaa64.efi" ;;
        *) echo "Error: Unknown arch '$arch'." >&2; return 1 ;;
    esac

    echo "Copying files from partition image '$P12_FILE'..."

    # Required: boot EFI binary.
    mcopy_from_p12 "$boot_src" "$BOOT_EFI_FILE" || return 1

    # Best-effort: default-mode extras. Skip silently when absent (uki).
    declare -A optional_files=(
        ["::/syslinux/vmlinuz.A"]="$VMLINUZ_A_FILE"
        ["::/efi/boot/grub.cfg"]="$GRUB_CFG_FILE"
        ["::/efi/boot/grub-lakitu.efi"]="$GRUB_EFI_FILE"
    )
    # vmlinuz.B file exists on amd64 but not on arm64
    if [ "$arch" == "x86_64" ]; then
        optional_files["::/syslinux/vmlinuz.B"]="$VMLINUZ_B_FILE"
    fi

    for src in "${!optional_files[@]}"; do
        local dest="${optional_files[$src]}"
        if mcopy -i "$P12_FILE" "$src" "$dest" 2>/dev/null; then
            echo "Copied '$src' to '$dest'."
        else
            echo "Skipped '$src' (not present in this image)."
        fi
    done
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

    local args=()

    while IFS= read -r line; do
        args+=("$line")
    done < <(xargs -n1 <<< "$cmdline_string")

    # Remove the first argument ('linux')
    args=("${args[@]:1}")

    if [ ${#args[@]} -eq 0 ]; then
        return 1
    fi

    for arg in "${args[@]}"; do
        if [[ "$arg" = *[[:space:]]* ]]; then
            result+=('"'"$arg"'"')
        else
            result+=("$arg")
        fi
    done

    printf '%s' "${result[*]}"
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
# Computes the Arm DRTM values for an arm64 Linux kernel EFI-stub image
# (bootaa64.efi) without needing vmlinux. On GB300 BMSAI, the NVIDIA PSC
# measures the kernel from _stext to _edata as the DLME, and the kernel
# measures its command line into DRTM PCR 19.
#   - _stext is read from the PE .text section VirtualAddress (and cross-checked
#     against kallsyms).
#   - _edata is extracted from the kernel's embedded kallsyms table. It is NOT
#     the end of the PE .data section.
#   - D = SHA384(image[_stext:_edata])  (DRTM PCR 18 event 0x9004, the DLME)
#   - Slot0 = SHA384(0^48 || D)         (PSC DRTM Slot 0, token claim 44238)
#   - The built-in command line (CONFIG_CMDLINE) is the NUL-terminated string
#     between _stext and _edata that contains 'cros_efi'. Its SHA-384 is the
#     DRTM PCR 19 CMDLINE event, one of the inputs to TEM0 (token claim
#     44239[0]).
# @param $1: Path to the arm64 kernel PE binary.
# @return Compact JSON object with stext_offset, edata_offset, dlme_sha384,
#         slot0_sha384, embedded_cmdline and embedded_cmdline_sha384 to stdout.
#
compute_arm64_drtm() {
    local kernel_file="$1"
    python3 - "$kernel_file" <<'PY'
import hashlib, json, re, struct, sys

path = sys.argv[1]
with open(path, "rb") as f:
    b = f.read()

if len(b) < 0x40 or b[0x38:0x3C] != b"ARM\x64":
    print(json.dumps({
        "stext_offset": "",
        "edata_offset": "",
        "dlme_sha384": "",
        "slot0_sha384": "",
        "embedded_cmdline": "",
        "embedded_cmdline_sha384": ""
    }))
    sys.exit(0)

# 1. Parse PE .text VirtualAddress (_stext - _text).
pe_off = struct.unpack_from("<I", b, 0x3C)[0]
nsec = struct.unpack_from("<H", b, pe_off + 6)[0]
opt_sz = struct.unpack_from("<H", b, pe_off + 20)[0]
sec_off = pe_off + 24 + opt_sz
stext_pe = None
for i in range(nsec):
    s = b[sec_off + 40 * i : sec_off + 40 * (i + 1)]
    name = s[:8].rstrip(b"\x00").decode("ascii", errors="replace")
    vsz, va, rawsz, rawptr = struct.unpack_from("<IIII", s, 8)
    if name == ".text":
        stext_pe = va
        break

if stext_pe is None:
    sys.stderr.write("Error: .text section not found in '%s'\n" % path)
    sys.exit(1)

# 2. Locate the embedded arm64 kallsyms table (Linux 6.x layout) to extract _edata.
def extract_kallsyms_bounds(img):
    tt_off = ti_off = None
    tokens = None
    for off in range(0, len(img) - 512, 8):
        if img[off:off+2] != b"\x00\x00":
            continue
        ti = struct.unpack_from("<256H", img, off)
        if not all(2 <= ti[i] - ti[i-1] <= 32 for i in range(1, 256)):
            continue
        for pad in range(1, 40):
            cand = off - ((ti[255] + pad + 7) & ~7)
            if cand < 0:
                continue
            if all(img[cand + ti[i] - 1] == 0 for i in range(1, 256)):
                toks = []
                ok = True
                for i in range(256):
                    end = img.find(b"\x00", cand + ti[i], off)
                    if end < 0 or (i < 255 and end != cand + ti[i+1] - 1):
                        ok = False
                        break
                    t = img[cand + ti[i]:end]
                    if not t or not all(0x20 <= b <= 0x7e for b in t):
                        ok = False
                        break
                    toks.append(t)
                if ok:
                    tt_off, ti_off, tokens = cand, off, toks
                    break
        if tt_off is not None:
            break
    if tt_off is None:
        return None, None

    m_end = tt_off
    if struct.unpack_from("<I", img, m_end - 4)[0] == 0:
        m_end -= 4
    pos = m_end - 4
    prev = struct.unpack_from("<I", img, pos)[0]
    markers_off = None
    while pos >= 4:
        cur = struct.unpack_from("<I", img, pos - 4)[0]
        if cur == 0 and (pos - 4) % 8 == 0 and 256 <= prev <= 65536:
            markers_off = pos - 4
            break
        prev = cur
        pos -= 4
    if markers_off is None:
        return None, None

    num_markers = (m_end - markers_off) // 4
    last_marker = struct.unpack_from("<I", img, m_end - 4)[0]
    start_scan = ((markers_off - last_marker) & ~7)
    num_syms = names_off = None
    for cand_num_off in range(start_scan, start_scan - 65536, -8):
        val, pad_zero = struct.unpack_from("<II", img, cand_num_off)
        if pad_zero == 0 and (val + 255) // 256 == num_markers:
            cand_names = cand_num_off + 8
            p = cand_names + last_marker
            rem = val - (num_markers - 1) * 256
            for _ in range(rem):
                if p >= markers_off:
                    p = -1
                    break
                l = img[p]
                p += 1
                if l & 0x80:
                    l = (l & 0x7f) | (img[p] << 7)
                    p += 1
                p += l
            if p > 0 and ((p + 7) & ~7) == markers_off:
                num_syms = val
                names_off = cand_names
                break
    if num_syms is None:
        return None, None

    offsets_off = ti_off + 512
    rel_base_off = (offsets_off + 4 * num_syms + 7) & ~7
    rel_base = struct.unpack_from("<Q", img, rel_base_off)[0]
    offs = struct.unpack_from(f"<{num_syms}i", img, offsets_off)
    want = {"_text", "_stext", "_edata"}
    found = {}
    p = names_off
    for i in range(num_syms):
        l = img[p]
        p += 1
        if l & 0x80:
            l = (l & 0x7f) | (img[p] << 7)
            p += 1
        s = b"".join(tokens[c] for c in img[p:p+l])
        p += l
        nm = s[1:].decode("latin1")
        if nm in want and nm not in found:
            found[nm] = rel_base + (offs[i] & 0xffffffff)
            if len(found) == len(want):
                break
    if "_text" in found and "_stext" in found and "_edata" in found:
        return found["_stext"] - found["_text"], found["_edata"] - found["_text"]
    return None, None

stext_ks, edata_ks = extract_kallsyms_bounds(b)
if stext_ks is None or edata_ks is None:
    sys.stderr.write("Error: Failed to locate embedded kallsyms _stext/_edata in '%s'\n" % path)
    sys.exit(1)
if stext_ks != stext_pe:
    sys.stderr.write("Error: kallsyms _stext (0x%x) != PE .text VA (0x%x)\n" % (stext_ks, stext_pe))
    sys.exit(1)

dlme_digest = hashlib.sha384(b[stext_ks:edata_ks]).digest()
slot0_digest = hashlib.sha384(b"\x00" * 48 + dlme_digest).digest()

embedded_cmd = ""
embedded_cmd_h = ""
for mm in re.finditer(b"cros_efi", b):
    s = b.rfind(b"\x00", 0, mm.start()) + 1
    e = b.find(b"\x00", mm.end())
    if e - s >= 64 and stext_ks <= s < edata_ks:
        embedded_cmd = b[s:e].decode("latin1")
        embedded_cmd_h = hashlib.sha384(b[s:e]).hexdigest()
        break

print(json.dumps({
    "stext_offset": hex(stext_ks),
    "edata_offset": hex(edata_ks),
    "dlme_sha384": dlme_digest.hex(),
    "slot0_sha384": slot0_digest.hex(),
    "embedded_cmdline": embedded_cmd,
    "embedded_cmdline_sha384": embedded_cmd_h
}))
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
		--arg drtm_stext "${15}" \
		--arg drtm_edata "${16}" \
		--arg drtm_dlme_a "${17}" \
		--arg drtm_slot0_a "${18}" \
		--arg tem0_cmd_a "${19}" \
		--arg tem0_cmd_a_h "${20}" \
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
			uki_efi: $uki_efi,
			drtm_stext_offset: $drtm_stext,
			drtm_edata_offset: $drtm_edata,
			drtm_dlme_a_sha384: $drtm_dlme_a,
			drtm_slot0_a_sha384: $drtm_slot0_a,
			tem0_cmdline_a: $tem0_cmd_a,
			tem0_cmdline_a_sha384: $tem0_cmd_a_h
		}' > "$output_json_file"

		if [[ $? -ne 0 || ! -s "$output_json_file" ]]; then
			echo "Error: Failed to create or write to output JSON file '$output_json_file'." >&2
			return 1
		fi
}

# --- Main Logic ---

main() {
    # 1. Parameter Handling & Initial Checks
    if [[ "$#" -ne 5 ]]; then
        echo "Usage: $0 <os_image_path> <output_json_file> <channel> <build_architecture> <hash_algo:sha256|sha384>"
        echo "Example: $0 /path/to/image.bin /path/to/output.json stable x86_64 sha384"
        return 1
    fi
    local os_image_path="$1"
    local output_json_file="$2"
    local channel="$3"
    local arch="$4"
    HASH_ALG="$5"

    if [[ ! -f "$os_image_path" ]]; then
        echo "Error: OS image path '$os_image_path' not found."
        return 1
    fi

    case "$HASH_ALG" in
        sha256) HASH_SUM_CMD="sha256sum" ;;
        sha384) HASH_SUM_CMD="sha384sum" ;;
        *) echo "Error: Unsupported hash algorithm '$HASH_ALG'. Use sha256 or sha384."; return 1 ;;
    esac

    check_dependencies || return 1

    # 2. Setup and Extraction
    setup_temp_dir
    extract_partition_12 "$os_image_path" || return 1
    extract_boot_components "$arch" || return 1
    local image_mode
    image_mode=$(detect_image_mode) || return 1
    echo "Auto-detected image_mode=$image_mode"

    # 3. Compute All Hashes
    echo "Computing all required hashes using $HASH_ALG (image_mode=$image_mode)..."
    local vmlinuz_a_hash="" vmlinuz_b_hash="" kernel_cmdline_a="" kernel_cmdline_b=""
    local kernel_cmdline_a_hash="" kernel_cmdline_b_hash=""
    local shim_hash="" grub_hash="" vmlinuz_a_pe_hash="" vmlinuz_b_pe_hash=""
    local uki_efi_hash=""
    local drtm_stext="" drtm_edata="" drtm_dlme_a="" drtm_slot0_a=""
    local tem0_cmd_a="" tem0_cmd_a_h=""

    if [ "$image_mode" == "uki" ]; then
        uki_efi_hash=$(compute_efi_authenticode_hash "$BOOT_EFI_FILE") || return 1
        echo "UKI bootx64.efi/bootaa64.efi hash: $uki_efi_hash"
        if [ "$arch" == "aarch64" ]; then
            local drtm_json
            drtm_json=$(compute_arm64_drtm "$BOOT_EFI_FILE") || return 1
            drtm_stext=$(jq -r '.stext_offset' <<< "$drtm_json")
            drtm_edata=$(jq -r '.edata_offset' <<< "$drtm_json")
            drtm_dlme_a=$(jq -r '.dlme_sha384' <<< "$drtm_json")
            drtm_slot0_a=$(jq -r '.slot0_sha384' <<< "$drtm_json")
            tem0_cmd_a=$(jq -r '.embedded_cmdline' <<< "$drtm_json")
            tem0_cmd_a_h=$(jq -r '.embedded_cmdline_sha384' <<< "$drtm_json")
            echo "arm64 DRTM DLME: $drtm_dlme_a (_stext=$drtm_stext, _edata=$drtm_edata)"
        fi
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
    fi

    # 4. Final Output with escaped kernel command line strings
    write_json_output "$output_json_file" "$channel" "$shim_hash" "$grub_hash" \
        "$vmlinuz_a_hash" "$vmlinuz_b_hash" "$kernel_cmdline_a_hash" "$kernel_cmdline_b_hash" \
        "$kernel_cmdline_a" "$kernel_cmdline_b" "$vmlinuz_a_pe_hash" "$vmlinuz_b_pe_hash" \
        "$image_mode" "$uki_efi_hash" \
        "$drtm_stext" "$drtm_edata" "$drtm_dlme_a" "$drtm_slot0_a" \
        "$tem0_cmd_a" "$tem0_cmd_a_h" || return 1

    echo "Measured boot hashes successfully written to '$output_json_file'."
}

main "$@"
