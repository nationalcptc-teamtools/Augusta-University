#!/usr/bin/env bash
# =============================================================================
#  hostprivesc.sh  —  Windows host privilege escalation triage  (COMPOSITE)
# =============================================================================
#  Attack-chain role: once you have a shell as a low-priv user on a Windows
#  host, this reads a WinPEAS output file and walks DOWN a ranked list of local
#  privesc techniques. For each it reports whether WinPEAS flagged the relevant
#  indicator, PAUSES, and names the staged tool/technique to try. It stops at
#  the first technique you confirm worked, unless --all is given.
#
#  This is a TRIAGE/decision aid (Kali-side). The actual escalation runs on the
#  target using the staged ~/tools/windows-payloads/ files.
#
#  Ranked order: SeImpersonate/Potato → service misconfig → unquoted service
#  path → AlwaysInstallElevated → stored creds/registry → missing patches.
#
#  Flags:
#    -f, --file <winpeas.txt>   WinPEAS output to analyze (required)
#    --all                      walk every technique, don't stop at first success
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
hostprivesc.sh — Windows host privesc triage from WinPEAS output (COMPOSITE)

USAGE:   ./hostprivesc.sh -f <winpeas-output.txt> [--all] [-t host]
EXAMPLE: ./hostprivesc.sh -f loot/ws01-winpeas.txt

FLAGS:
  -f, --file <winpeas.txt>  WinPEAS output to analyze (required)
      --all                 walk all six techniques; don't stop at first success
  -h, --help                this help
  (shared flags: --help-common)

WHAT IT DOES: reads the WinPEAS file and walks a ranked list (SeImpersonate/
  Potato -> service misconfig -> unquoted service path -> AlwaysInstallElevated
  -> stored creds/registry -> missing patches), pausing before each, reporting
  whether WinPEAS flagged it, and naming the staged tool to use. Triage only —
  the actual escalation runs on the target with ~/tools/windows-payloads/.
PREREQS: a WinPEAS output file (run the staged winPEAS.ps1 on the target first).
EOF
}

PAYLOADS="${PAYLOADS:-$HOME/tools/windows-payloads}"
PEAS_FILE="" CONTINUE_ALL=0

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file) PEAS_FILE="$2"; shift 2 ;;
    --all) CONTINUE_ALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

log_begin

# A WinPEAS output file is required to triage. If it's missing, point the
# operator at the staged enumerator and stop (nothing to analyze).
if [[ -z "$PEAS_FILE" || ! -f "$PEAS_FILE" ]]; then
  [[ -n "$PEAS_FILE" ]] && log_warn "WinPEAS file not found: ${PEAS_FILE}"
  log_warn "No WinPEAS output to analyze. Run the staged enumerator on the target"
  log_warn "(${PAYLOADS}/privesc/winPEAS.ps1), save its output to a file, then re-run with -f <file>."
  log_end "partial"; exit 0
fi
log_info "analyzing WinPEAS output: ${PEAS_FILE}"

# ----------------------------------------------------------------------------
# Each technique: a name, a case-insensitive grep pattern that indicates WinPEAS
# saw something relevant, and a one-line pointer to the staged tool to use.
# `check_indicator` reports hits (and logs a short excerpt) without dumping the
# whole file into the master log.
# ----------------------------------------------------------------------------
check_indicator() {                 # check_indicator <pattern> ; returns 0 if found
  grep -Eiq "$1" "$PEAS_FILE"
}
show_excerpt() {                    # log up to 8 matching lines as evidence
  local hits; hits="$(grep -Ein "$1" "$PEAS_FILE" | head -n 8)"
  [[ -n "$hits" ]] && master_raw "    indicator lines:
${hits}"
}

# technique <name> <grep-pattern> <guidance>
technique() {
  local name="$1" pat="$2" guide="$3"
  local found="no"; check_indicator "$pat" && found="yes"
  if ! pause_step "${name}  (WinPEAS indicator: ${found})"; then
    return 1   # skipped
  fi
  if [[ "$found" == "yes" ]]; then
    log_ok "WinPEAS flagged an indicator for: ${name}"
    show_excerpt "$pat"
  else
    log_info "no WinPEAS indicator for ${name} — try anyway only if you have other signal"
  fi
  log_info "approach: ${guide}"
  if confirm "Did ${name} succeed in getting you elevated?"; then
    log_ok "SUCCESS via ${name}"
    return 0   # success
  fi
  return 1     # attempted, not successful
}

# ----------------------------------------------------------------------------
# Ranked techniques. Guidance names the staged tool + the misconfig class;
# the operator runs it on the target.
# ----------------------------------------------------------------------------
declare -a RESULT_LOG=()
succeeded=""

try() {
  local name="$1"; shift
  if technique "$name" "$@"; then
    succeeded="$name"; RESULT_LOG+=("$name: SUCCESS")
    return 0
  fi
  RESULT_LOG+=("$name: not successful / skipped")
  return 1
}

run_all() {
  # 1) Token-impersonation privileges → Potato-family tools.
  try "SeImpersonate / Potato" \
      'SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege' \
      "SeImpersonate present → use the staged ${PAYLOADS}/privesc/PrintSpoofer64.exe or GodPotato-NET4.exe to run a command as SYSTEM." \
      && [[ "$CONTINUE_ALL" -eq 0 ]] && return 0

  # 2) Modifiable/misconfigured service.
  try "Service misconfiguration" \
      'You can (modify|start|stop)|modifiable|WRITE.*service|service.*permissions|RWX|LocalSystem' \
      "A service you can modify → reconfigure its binary path to your payload and restart it (runs as the service account, often SYSTEM)." \
      && [[ "$CONTINUE_ALL" -eq 0 ]] && return 0

  # 3) Unquoted service path.
  try "Unquoted service path" \
      'unquoted|No quotes and Space detected' \
      "Unquoted path with a writable intermediate dir → drop a payload named for the first space-truncated segment." \
      && [[ "$CONTINUE_ALL" -eq 0 ]] && return 0

  # 4) AlwaysInstallElevated.
  try "AlwaysInstallElevated" \
      'AlwaysInstallElevated.*(1|enabled|true)' \
      "Both AlwaysInstallElevated keys set → install a crafted .msi which executes elevated." \
      && [[ "$CONTINUE_ALL" -eq 0 ]] && return 0

  # 5) Stored credentials / registry secrets.
  try "Stored credentials / registry secrets" \
      'cpassword|DefaultPassword|AutoLogon|cmdkey|stored cred|Credential Manager|_password|unattend' \
      "Harvested secrets (autologon, saved RDP/cmdkey creds, unattend) → reuse them; add any to creds.json." \
      && [[ "$CONTINUE_ALL" -eq 0 ]] && return 0

  # 6) Missing patches / known exploits.
  try "Missing patches / known exploits" \
      'CVE-[0-9]|not patched|vulnerable|Hotfix|KB[0-9]{6,}' \
      "Patch gaps noted → confirm with a patch-level check (wesng/Watson) and match to a known local exploit." \
      && [[ "$CONTINUE_ALL" -eq 0 ]] && return 0

  return 1
}

run_all

# Summary of this triage pass.
master_raw "  --- privesc triage summary ---"
for r in "${RESULT_LOG[@]}"; do master_raw "    ${r}"; done
if [[ -n "$succeeded" ]]; then
  log_ok "elevated via: ${succeeded}"
else
  log_warn "no technique confirmed successful this pass (re-run with --all to walk all six)"
fi

log_end "success"
