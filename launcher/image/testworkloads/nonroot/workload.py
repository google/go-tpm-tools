import argparse
import ctypes
import os
import socket
import sys
import time


_SERVER_PORT = 2020


def set_proc_name(name):
    """Sets the process name."""
    libc = ctypes.CDLL(None)
    libc.prctl(15, name.encode("utf-8"), 0, 0, 0)


def run_child(name, uid):
    set_proc_name(name)
    try:
        os.setuid(uid)
    except Exception as e:
        print(f"Setuid error: {e}", file=sys.stderr)
    while True:
        time.sleep(1)


def get_proc_info(pid):
    """Reads process name and UID from /proc/[pid]."""
    with open(os.path.join("/proc", str(pid), "comm"), "r") as f:
        comm = f.read().strip()

    with open(os.path.join("/proc", str(pid), "status"), "r") as f:
        for line in f:
            if line.startswith("Uid:"):
                parts = line.split()
                # parts[1] is Real UID, parts[2] is Effective UID
                uid = parts[1]
                break
    return f"{comm}: {uid}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", "-ip", default="")
    args, _ = parser.parse_known_args()

    if not args.ip:
        sys.exit("error: --ip flag is required")

    set_proc_name("fork-parent")

    # Child 1
    pid1 = os.fork()
    if pid1 == 0:
        run_child("fork-child1", 101)

    # Fork Child 2
    pid2 = os.fork()
    if pid2 == 0:
        run_child("fork-child2", 909)

    # Parent process gives children a moment to apply setuid and rename
    time.sleep(0.5)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    lines = [
        get_proc_info(os.getpid()),
        get_proc_info(pid1),
        get_proc_info(pid2),
    ]
    process_tree = "\n".join(lines) + "\n"

    print(f"Sending process tree:\n{process_tree.strip()}", file=sys.stderr)
    try:
        sock.sendto(process_tree.encode("utf-8"), (args.ip, _SERVER_PORT))
    except Exception as e:
        print(f"UDP send error: {e}", file=sys.stderr)

    time.sleep(300)  # Wait 5 minutes before die


if __name__ == "__main__":
    main()
