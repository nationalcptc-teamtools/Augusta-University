#!/usr/bin/env bash
# =============================================================================
#  recon_advanced.sh  —  deep follow-up enumeration via AutoRecon  (ATOMIC)
# =============================================================================
#  Attack-chain role: the deeper, slower follow-up to 01_recon.sh. AutoRecon
#  runs its own port scan and then fans out per-service enumeration plugins
#  automatically. 01_recon.sh stays the fast initial sweep; this is the
#  thorough pass once you know a host is worth the time.
#
#  Output goes into this run's loot directory.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
recon_advanced.sh — deep AutoRecon follow-up enumeration (ATOMIC)

USAGE:   ./recon_advanced.sh [-t target|cidr] [-q]
EXAMPLE: ./recon_advanced.sh -t 10.129.158.181

FLAGS:
  -t, --target <ip|cidr>  target (default: first scope.txt line)
  -q, --quiet             no live screen output (log still complete)
  -h, --help              this help
  (shared flags: --help-common)

WHAT IT DOES: runs AutoRecon against the target with output written under the
  run's loot dir (autorecon -o <loot>/autorecon). Separate from 01_recon.sh
  (the fast sweep) — this is the slower, thorough automated follow-up and can
  take a while.
PREREQS: a target; AutoRecon installed (autorecon). May want root for some
  AutoRecon scans.
EOF
}

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <target>"

log_begin
announce_loot
need_cmd autorecon
OUT="$(loot_dir)/autorecon"
mkdir -p "$OUT"

log_info "AutoRecon against ${TARGET} (this can take a while) → ${OUT}"
run_cmd "autorecon -o $(printf '%q' "$OUT") ${TARGET}"
if [[ "$LAST_RC" -eq 0 ]]; then
  log_ok "AutoRecon finished → results under ${OUT}"
else
  log_warn "AutoRecon exited non-zero (${LAST_RC}) — partial results may still be under ${OUT}"
fi
log_end "success"
