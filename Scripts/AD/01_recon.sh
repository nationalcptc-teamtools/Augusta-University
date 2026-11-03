#!/usr/bin/env bash
# =============================================================================
#  01_recon.sh  —  host discovery + full nmap port/service sweep  (ATOMIC)
# =============================================================================
#  Attack-chain role: the opening move. Finds live hosts and every open TCP
#  port/service on the resolved target, and records the open ports to a shared
#  state file so the enumeration scripts can gate service-specific steps
#  (e.g. SNMP only when 161 is open).
#
#  Runs straight through (no pauses). Invoking it is the confirmation.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
01_recon.sh — host discovery + full nmap port/service sweep (ATOMIC, no pauses)

USAGE:   ./01_recon.sh [-t target|cidr] [-q]
EXAMPLE: ./01_recon.sh -t 10.129.158.165

FLAGS:
  -t, --target <ip|cidr>  target to scan (default: first scope.txt line)
  -q, --quiet             no live screen output (master.log still complete)
  -h, --help              this help
  (shared flags: --help-common)

WHAT IT DOES: nmap -sn sweep, then -Pn -p- -sV -sC. Records open ports to
  state/<target>.ports so later scripts can gate on them (SNMP 161, WinRM 5985).
PREREQS: a target (scope.txt or -t); nmap.
EOF
}

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }

[[ -n "$TARGET" ]] || die "no target: set a line in scope.txt or pass -t <target>"

log_begin
need_cmd nmap

# 1) Host discovery (ping sweep). Most useful for a CIDR; harmless for one host.
run_cmd "nmap -sn -n ${TARGET} -oG '${RUN_DIR}/hosts.gnmap'" \
  || log_warn "host discovery returned non-zero (continuing to port sweep)"

# 2) Full TCP sweep with service/version detection + default scripts.
#    -Pn: don't re-probe liveness (we already swept);  -p-: all 65535 ports;
#    --min-rate keeps it fast under the clock.  -oA writes all three formats.
run_cmd "nmap -Pn -n -p- --min-rate 2000 -sV -sC ${TARGET} -oA '${RUN_DIR}/nmap'" \
  || log_warn "nmap sweep returned non-zero (parsing whatever completed)"

# 3) Parse open ports from the greppable output and persist them.
PORTS_RESULT="${RUN_DIR}/open-ports.txt"
if [[ -f "${RUN_DIR}/nmap.gnmap" ]]; then
  grep -hoE '[0-9]+/open' "${RUN_DIR}/nmap.gnmap" | cut -d/ -f1 | sort -un > "$PORTS_RESULT"
else
  : > "$PORTS_RESULT"
fi

if [[ -s "$PORTS_RESULT" ]]; then
  while read -r p; do record_open_port "$p"; done < "$PORTS_RESULT"
  log_ok "open ports on ${TARGET}: $(paste -sd' ' "$PORTS_RESULT")"
  log_info "state updated: $(ports_file)"
else
  log_warn "no open ports parsed (check ${RUN_DIR}/nmap.nmap)"
fi

log_info "recon artifacts in ${RUN_DIR} (open-ports.txt, nmap.*)"
log_end "success"
