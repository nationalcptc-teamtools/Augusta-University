#!/usr/bin/env bash
#
# =============================================================================
#  CPTC — Windows / Active Directory Attack-Chain Kali Setup
# =============================================================================
#  Role coverage: recon -> enumeration -> exploitation -> lateral movement ->
#                 domain-level persistence (initial foothold through DC root).
#
#  Target environment : freshly provisioned Kali Linux box (RDP/SSH), run live
#                        at/just before the assessment window. Assumes root/sudo
#                        and general internet access to public repos only.
#
#  Design goals:
#    * One script, labelled sections, each independently callable (flag/function)
#    * Idempotent  — safe to re-run; skips anything already installed & working
#    * Logged      — timestamped log file of installed/skipped/retried/failed
#    * Retried     — up to 3 attempts, preferring a DIFFERENT method each retry
#    * Verified    — functional check per tool where practical (not just "exists")
#    * Graceful    — one tool's failure logs & continues, never aborts the run
#    * Summarised  — final pass/fail table + attack-chain readiness notes
#
#  Usage:
#    ./cptc-ad-setup.sh                 # run every section, staged mode
#    ./cptc-ad-setup.sh --stealth       # run every section, stealth mode
#    ./cptc-ad-setup.sh recon ad        # run only the named section(s)
#    ./cptc-ad-setup.sh --section recon --section payloads
#    ./cptc-ad-setup.sh --list          # list section names
#    ./cptc-ad-setup.sh --help
#
#  Section names: prep recon ad coercion creds payloads wordlists persistence
# =============================================================================

# NOTE: we deliberately do NOT use `set -e`. Failures are handled per-tool so a
# single failure never aborts the whole run. `set -u` is also avoided because of
# associative-array existence checks on older bash.
set -o pipefail

# -----------------------------------------------------------------------------
#  0. Global configuration
# -----------------------------------------------------------------------------

# STEALTH toggle. A single switch affecting Mimikatz + Rubeus consistently.
#   0 = staged mode  : download & stage Mimikatz + Rubeus, ready to deliver
#   1 = stealth mode : skip staging them; summary notes the Kali-side
#                      Impacket alternatives instead (no binary touches target)
# Override at the top here, or pass --stealth on the command line.
STEALTH=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TOOLS_DIR="$HOME/tools"
PAYLOADS_DIR="$TOOLS_DIR/windows-payloads"
LOG_DIR="$SCRIPT_DIR/logs"
TS="$(date '+%Y%m%d-%H%M%S')"
LOGFILE="$LOG_DIR/cptc-setup-$TS.log"
TMPD="$(mktemp -d "${TMPDIR:-/tmp}/cptc-setup.XXXXXX")"

# Use sudo for privileged ops when we are not already root.
SUDO=""
[[ "${EUID:-$(id -u)}" -ne 0 ]] && SUDO="sudo"

# pipx / local binaries live here.
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
export DEBIAN_FRONTEND=noninteractive

# Result tracking.
declare -A RESULTS       # name -> PASS|FAIL|SKIP
declare -A RESULT_NOTE   # name -> free-text detail
TOOL_ORDER=()            # preserves display order
NOTES=()                 # attack-chain readiness notes for the summary

APT_UPDATED=0

# Colours (disabled with --no-color or when not a TTY).
if [[ -t 1 ]]; then
  C_RESET=$'\e[0m'; C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
  C_CYN=$'\e[36m'; C_BOLD=$'\e[1m'
else
  C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_BOLD=""
fi

cleanup() { rm -rf "$TMPD" 2>/dev/null; }
trap cleanup EXIT

# -----------------------------------------------------------------------------
#  1. Core helpers: logging, verification, retry, result tracking
# -----------------------------------------------------------------------------

log() {                     # log <LEVEL> <message...>
  local level="$1"; shift
  local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
  local color=""
  case "$level" in
    OK)    color="$C_GRN" ;;
    SKIP)  color="$C_CYN" ;;
    WARN)  color="$C_YEL" ;;
    ERROR) color="$C_RED" ;;
    *)     color="" ;;
  esac
  # Coloured to the terminal, plain to the log file.
  echo "${color}[$ts] [$level] $*${C_RESET}"
  echo "[$ts] [$level] $*" >>"$LOGFILE"
}

record() {                  # record <name> <PASS|FAIL|SKIP> <detail>
  local name="$1" status="$2" detail="$3"
  if [[ -z "${RESULTS[$name]+x}" ]]; then TOOL_ORDER+=("$name"); fi
  RESULTS["$name"]="$status"
  RESULT_NOTE["$name"]="$detail"
}

note() { NOTES+=("$1"); }   # queue an attack-chain readiness note

# verify <cmd-string>  -> returns 0 if the functional check passes.
# Encode "must produce output" directly in the command (e.g. `... | grep -q .`)
# so we test real functionality, not just command existence.
verify() { eval "$1" >/dev/null 2>&1; }

has_cmd_any() { local c; for c in "$@"; do command -v "$c" >/dev/null 2>&1 && return 0; done; return 1; }

# verify_runs <command> [args...]
# Functional check that is robust to --version/-h output quirks: the tool counts
# as working if it is on PATH AND actually launches (exit status is not 127
# "not found" / 126 "not executable"). This exercises the real binary without
# depending on the exact text or stream a given tool prints for its version flag
# — several tools (e.g. netexec, certipy) print nothing useful to a naive
# `--version | grep .` check even though they are installed and functional.
verify_runs() {
  command -v "$1" >/dev/null 2>&1 || return 1
  local rc
  timeout 30 "$@" >/dev/null 2>&1; rc=$?
  [[ $rc -ne 126 && $rc -ne 127 ]]
}

# apt helpers — update index once per process, install non-interactively.
apt_update_once() {
  if [[ $APT_UPDATED -eq 0 ]]; then
    log INFO "Refreshing apt package index..."
    $SUDO apt-get update -y >>"$LOGFILE" 2>&1 || log WARN "apt-get update returned non-zero (continuing)"
    APT_UPDATED=1
  fi
}
apt_install() { apt_update_once; $SUDO apt-get install -y "$@" >>"$LOGFILE" 2>&1; }

# Ensure pipx exists (isolated installs for the AD python tooling — never system
# pip, because Kali's system Python is PEP 668 externally-managed and impacket's
# ldap3/pyasn1 chain collides with apt's packages).
ensure_pipx() {
  if ! command -v pipx >/dev/null 2>&1; then
    apt_install pipx || python3 -m pip install --user pipx --break-system-packages >>"$LOGFILE" 2>&1
  fi
  export PATH="$HOME/.local/bin:$PATH"
  pipx ensurepath >>"$LOGFILE" 2>&1 || true
}

# Download helper: follow redirects, fail on HTTP error, a couple of curl-level
# retries for transient network blips.
fetch() {                   # fetch <url> <outfile>
  curl -fsSL --retry 2 --connect-timeout 20 -o "$2" "$1"
}

# pick the available docker-compose implementation (plugin or standalone)
dc() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  else docker-compose "$@"; fi
}

# -----------------------------------------------------------------------------
#  install_tool: the generic idempotent / retry / verify engine
#
#    install_tool <name> <verify-cmd> <method1> [method2] [method3]
#
#  Behaviour:
#    * If verify passes up front  -> SKIP (already installed & functional).
#    * Otherwise try methods in order. Up to 3 attempts total. Where fewer than
#      3 distinct methods are given, the last one is repeated to reach 3 (pure
#      repetition fallback — used only when no alternate method exists).
#    * After each attempt, re-run verify. First success -> PASS (records which
#      attempt/method worked). Exhausted -> FAIL (logged, run continues).
# -----------------------------------------------------------------------------
install_tool() {
  local name="$1"; shift
  local verify_cmd="$1"; shift
  local methods=("$@")

  log INFO "=== ${C_BOLD}$name${C_RESET} ==="

  if verify "$verify_cmd"; then
    log SKIP "$name already present and functional — skipping"
    record "$name" SKIP "already present"
    return 0
  fi

  # Normalise to exactly 3 attempts, padding with the last method when there is
  # no alternate (so a transient failure still gets retried).
  local attempts=() idx
  for idx in 0 1 2; do
    if (( idx < ${#methods[@]} )); then attempts+=("${methods[$idx]}")
    else attempts+=("${methods[$(( ${#methods[@]} - 1 ))]}"); fi
  done

  local i=0 m
  for m in "${attempts[@]}"; do
    i=$((i+1))
    log INFO "$name: attempt $i/3 -> $m"
    if eval "$m" >>"$LOGFILE" 2>&1; then
      if verify "$verify_cmd"; then
        log OK "$name installed & verified (attempt $i)"
        record "$name" PASS "method $i: ${m%% *}"
        return 0
      else
        log WARN "$name: attempt $i ran but functional verification failed"
      fi
    else
      log WARN "$name: attempt $i install command failed (see log)"
    fi
  done

  log ERROR "$name: FAILED after 3 attempts — manual attention needed"
  record "$name" FAIL "3 attempts exhausted"
  return 1
}

# idempotent git clone (shallow); pulls if already present
git_clone_idem() {          # git_clone_idem <url> <dest>
  if [[ -d "$2/.git" ]]; then ( cd "$2" && git pull --ff-only )
  else git clone --depth 1 "$1" "$2"; fi
}

# =============================================================================
#  SECTION: system prep  (base/session tooling + docker for BloodHound CE)
# =============================================================================
sec_prep() {
  log INFO "########## SECTION: system prep ##########"

  # Terminal multiplexing / session comfort under time pressure.
  install_tool "terminator"    "has_cmd_any terminator"            "apt_install terminator"
  install_tool "tmux"          "tmux -V | grep -q ."               "apt_install tmux"
  install_tool "git"           "git --version | grep -q ."         "apt_install git"
  install_tool "jq"            "jq --version | grep -q ."          "apt_install jq"
  install_tool "curl"          "curl --version | grep -q ."        "apt_install curl"
  install_tool "unzip"         "unzip -v | grep -q ."              "apt_install unzip"

  # pipx + venv underpin the isolated AD python tooling (impacket et al.)
  install_tool "pipx"          "pipx --version | grep -q ." \
      "apt_install pipx" \
      "apt_install python3-pipx" \
      "python3 -m pip install --user pipx --break-system-packages"
  install_tool "python3-venv"  "python3 -c 'import venv' 2>/dev/null && dpkg -s python3-venv >/dev/null 2>&1 || python3 -m venv $TMPD/_venvtest" \
      "apt_install python3-venv"

  # Docker — required to run BloodHound CE (Community Edition) later.
  install_tool "docker"        "docker --version | grep -q ." \
      "apt_install docker.io" \
      "apt_install docker.io"
  # Best-effort: bring the docker daemon up (ignored where systemd is absent).
  $SUDO systemctl enable --now docker >>"$LOGFILE" 2>&1 || log WARN "could not enable docker via systemctl (continuing)"

  # docker-compose — BloodHound CE ships as a compose stack. Accept either the
  # standalone binary or the v2 plugin.
  install_tool "docker-compose" "dc version 2>/dev/null | grep -q . || docker-compose --version 2>/dev/null | grep -q ." \
      "apt_install docker-compose" \
      "apt_install docker-compose-plugin" \
      "apt_install docker-compose-v2"
}

# =============================================================================
#  SECTION: recon & enumeration
# =============================================================================
sec_recon() {
  log INFO "########## SECTION: recon & enumeration ##########"
  ensure_pipx

  # nmap — host/service/port discovery, the opening sweep.
  install_tool "nmap"          "nmap --version | grep -q ."        "apt_install nmap"

  # AutoRecon — orchestrates the initial multi-service scan/enum sweep.
  install_tool "autorecon"     "has_cmd_any autorecon" \
      "pipx install git+https://github.com/Tib3rius/AutoRecon.git" \
      "pipx install autorecon" \
      "apt_install autorecon"

  # netexec (nxc) — the SMB/LDAP/WinRM swiss-army knife for AD enum & spraying.
  install_tool "netexec"       "verify_runs netexec --version || verify_runs nxc --version" \
      "pipx install git+https://github.com/Pennyw0rth/NetExec" \
      "apt_install netexec" \
      "pipx install netexec"

  # Samba client stack — rpcclient / smbclient for null-session & share recon.
  install_tool "smbclient"     "smbclient --version | grep -q ."   "apt_install smbclient"
  install_tool "rpcclient"     "has_cmd_any rpcclient"             "apt_install samba-common-bin" "apt_install smbclient"
  # smbmap — quick share permission mapping.
  install_tool "smbmap"        "smbmap -h 2>&1 | grep -q ." \
      "apt_install smbmap" \
      "pipx install smbmap" \
      "pipx install git+https://github.com/ShawnDEvans/smbmap.git"

  # enum4linux-ng — consolidated SMB/LDAP/RPC enumeration.
  install_tool "enum4linux-ng" "enum4linux-ng -h 2>&1 | grep -q ." \
      "pipx install enum4linux-ng" \
      "apt_install enum4linux-ng" \
      "pipx install git+https://github.com/cddmp/enum4linux-ng.git"

  # kerbrute — Kerberos pre-auth user enumeration + password spraying.
  # No apt package; install the official release binary into /usr/local/bin.
  install_tool "kerbrute"      "kerbrute --help 2>&1 | grep -qi kerbrute" \
      "fetch 'https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64' '$TMPD/kerbrute' && chmod +x '$TMPD/kerbrute' && $SUDO install -m0755 '$TMPD/kerbrute' /usr/local/bin/kerbrute"

  # ldapdomaindump — dump AD users/groups/computers over LDAP to HTML/JSON.
  install_tool "ldapdomaindump" "ldapdomaindump -h 2>&1 | grep -q ." \
      "pipx install ldapdomaindump" \
      "apt_install ldapdomaindump" \
      "pipx install git+https://github.com/dirkjanm/ldapdomaindump.git"

  # bloodhound-python — the Python ingestor/collector (works with CE or legacy).
  install_tool "bloodhound-python" "bloodhound-python --help 2>&1 | grep -q ." \
      "pipx install bloodhound" \
      "apt_install bloodhound.py" \
      "pipx install git+https://github.com/dirkjanm/BloodHound.py.git"

  # BloodHound CE (Docker) as primary; legacy (Neo4j + GUI) as the fallback.
  install_bloodhound
}

# BloodHound: try CE (docker compose stack) up to 3 times, then fall back to
# legacy BloodHound (neo4j + the old desktop app). Log clearly which landed,
# since day-of usage differs between the two.
install_bloodhound() {
  log INFO "=== ${C_BOLD}BloodHound${C_RESET} ==="
  local bh_dir="$TOOLS_DIR/bloodhound-ce"
  local cf="$bh_dir/docker-compose.yml"

  # Already set up (CE stack present)?
  if [[ -s "$cf" ]] && ( cd "$bh_dir" && dc config >/dev/null 2>&1 ); then
    log SKIP "BloodHound CE compose stack already staged"
    record "BloodHound" SKIP "CE (docker) already staged"
    note "BloodHound = Community Edition (Docker). Start with: cd $bh_dir && $(command -v docker >/dev/null && echo 'docker compose') up -d  then browse http://localhost:8080"
    return 0
  fi

  mkdir -p "$bh_dir"
  local i
  for i in 1 2 3; do
    log INFO "BloodHound CE: attempt $i/3 (fetch compose + pull images)"
    if ( fetch "https://ghst.ly/getbhce" "$cf" \
          || fetch "https://github.com/SpecterOps/BloodHound/raw/main/examples/docker-compose/docker-compose.yml" "$cf" ) \
       && [[ -s "$cf" ]] \
       && ( cd "$bh_dir" && dc pull >>"$LOGFILE" 2>&1 ); then
      log OK "BloodHound CE staged & images pulled (attempt $i)"
      record "BloodHound" PASS "CE (Docker)"
      note "BloodHound = Community Edition (Docker). Start with: cd $bh_dir && docker compose up -d  then browse http://localhost:8080 (default creds set on first boot)."
      return 0
    fi
    log WARN "BloodHound CE: attempt $i failed"
  done

  # ---- Fallback: legacy BloodHound (Neo4j + old Electron GUI) ----
  log WARN "BloodHound CE failed after 3 attempts — falling back to legacy BloodHound"
  if apt_install bloodhound neo4j && has_cmd_any neo4j bloodhound; then
    log OK "Legacy BloodHound installed (neo4j + GUI)"
    record "BloodHound" PASS "LEGACY (neo4j + GUI)"
    note "BloodHound = LEGACY build (Neo4j + desktop GUI) — CE install failed. Start Neo4j: $SUDO neo4j console  (default neo4j/neo4j, set a new pw), then launch 'bloodhound'. NOTE: usage differs from CE."
  else
    log ERROR "BloodHound: both CE and legacy installs failed"
    record "BloodHound" FAIL "CE and legacy both failed"
  fi
}

# =============================================================================
#  SECTION: AD exploitation  (impacket & dependents — ISOLATED via pipx/venv)
#
#  Kali's system Python is PEP 668 externally-managed, and impacket's
#  ldap3/pyasn1 chain has known version-collision ImportErrors when mixed with
#  apt's system packages. Everything here is installed in its own isolated
#  environment via pipx — never system pip.
# =============================================================================
sec_ad() {
  log INFO "########## SECTION: AD exploitation ##########"
  ensure_pipx

  # impacket — the core AD exploitation suite. pipx gives it an isolated venv.
  # Provides: GetNPUsers (AS-REP roast), GetUserSPNs (Kerberoast), secretsdump
  # (DCSync/SAM/LSA), ticketer (Golden Ticket), getTGT, ticketConverter,
  # psexec/wmiexec (exec), addcomputer, rbcd, lookupsid, raiseChild, smbserver,
  # and all the example scripts.
  install_tool "impacket"      "has_cmd_any impacket-secretsdump secretsdump.py" \
      "pipx install impacket" \
      "pipx install git+https://github.com/fortra/impacket.git" \
      "install_impacket_venv"

  # certipy-ad — AD CS enumeration & abuse (ESC1-ESC11), and AD CS persistence.
  install_tool "certipy-ad"    "verify_runs certipy -h || verify_runs certipy version" \
      "pipx install certipy-ad" \
      "pipx install git+https://github.com/ly4k/Certipy.git"

  # bloodyad — LDAP-based AD privilege-escalation / object manipulation.
  install_tool "bloodyad"      "bloodyad --help 2>&1 | grep -q ." \
      "pipx install bloodyad" \
      "pipx install git+https://github.com/cravaterouge/bloodyad.git"

  # gpp-decrypt — decrypt cached GPP cpassword (SYSVOL) credentials.
  install_tool "gpp-decrypt"   "has_cmd_any gpp-decrypt"           "apt_install gpp-decrypt"

  # Hash cracking — usually pre-installed on Kali; verify, install if missing,
  # never fail the run if already present.
  install_tool "hashcat"       "hashcat --version | grep -q ."     "apt_install hashcat"
  install_tool "john"          "john --list=build-info 2>&1 | grep -q . || john 2>&1 | grep -qi john" "apt_install john"
  install_tool "hashid"        "hashid --version 2>&1 | grep -q . || echo test | hashid 2>&1 | grep -q ." "apt_install hashid"

  # evil-winrm — interactive WinRM shell for lateral movement / post-ex.
  install_tool "evil-winrm"    "has_cmd_any evil-winrm" \
      "$SUDO gem install evil-winrm" \
      "apt_install evil-winrm" \
      "$SUDO gem install evil-winrm"
}

# Method-3 fallback for impacket: a clean isolated venv, with the example
# scripts symlinked into /usr/local/bin as impacket-<name> so verification and
# day-of usage match the pipx layout.
install_impacket_venv() {
  local venv="$HOME/.impacket-venv"
  python3 -m venv "$venv" || return 1
  "$venv/bin/pip" install --upgrade pip wheel >>"$LOGFILE" 2>&1
  "$venv/bin/pip" install impacket || return 1
  local f base
  for f in "$venv"/bin/*.py; do
    [[ -e "$f" ]] || continue
    base="$(basename "$f" .py)"
    $SUDO ln -sf "$f" "/usr/local/bin/impacket-$base"
  done
  has_cmd_any impacket-secretsdump
}

# =============================================================================
#  SECTION: DC coercion / NTLM relay chain  (git clone — not packaged)
# =============================================================================
sec_coercion() {
  log INFO "########## SECTION: DC coercion / NTLM relay ##########"
  mkdir -p "$TOOLS_DIR"

  # PetitPotam — MS-EFSRPC coercion to force DC authentication (relay target).
  install_tool "PetitPotam"    "test -f '$TOOLS_DIR/PetitPotam/PetitPotam.py'" \
      "git_clone_idem https://github.com/topotam/PetitPotam.git '$TOOLS_DIR/PetitPotam'"

  # krbrelayx — Kerberos relay / unconstrained-delegation abuse. This repo ALSO
  # bundles printerbug.py (MS-RPRN coercion), so no separate printerbug clone.
  install_tool "krbrelayx"     "test -f '$TOOLS_DIR/krbrelayx/krbrelayx.py' && test -f '$TOOLS_DIR/krbrelayx/printerbug.py'" \
      "git_clone_idem https://github.com/dirkjanm/krbrelayx.git '$TOOLS_DIR/krbrelayx'"
}

# =============================================================================
#  SECTION: post-foothold / credential hunting
# =============================================================================
sec_creds() {
  log INFO "########## SECTION: post-foothold / credential hunting ##########"
  mkdir -p "$TOOLS_DIR/snaffler"

  # Snaffler — hunts shares/filesystems for credentials & secrets. C# tool;
  # grab the compiled release binary (do NOT build from source).
  install_tool "Snaffler"      "test -s '$TOOLS_DIR/snaffler/Snaffler.exe'" \
      "fetch 'https://github.com/SnaffCon/Snaffler/releases/latest/download/Snaffler.exe' '$TOOLS_DIR/snaffler/Snaffler.exe'"
}

# =============================================================================
#  SECTION: Windows payload staging
#
#  These run on compromised WINDOWS hosts, not Kali. Stage them as ready-to-serve
#  files under ~/tools/windows-payloads/, grouped by purpose. Prefer compiled
#  GitHub release binaries over cloning full source.
#
#  Mimikatz + Rubeus are gated by the STEALTH toggle (see top of script).
# =============================================================================
sec_payloads() {
  log INFO "########## SECTION: Windows payload staging ##########"
  local privesc="$PAYLOADS_DIR/privesc"
  local enum="$PAYLOADS_DIR/enum"
  local creds="$PAYLOADS_DIR/creds"
  local persist="$PAYLOADS_DIR/persistence"
  mkdir -p "$privesc" "$enum" "$creds" "$persist"

  # ---- privesc/ : local privilege escalation on the Windows host ----
  # PrintSpoofer — SeImpersonate -> SYSTEM via the print spooler named pipe.
  install_tool "PrintSpoofer64.exe" "test -s '$privesc/PrintSpoofer64.exe'" \
      "fetch 'https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe' '$privesc/PrintSpoofer64.exe'"
  # GodPotato — SeImpersonate -> SYSTEM (modern Potato, .NET4 build).
  install_tool "GodPotato-NET4.exe" "test -s '$privesc/GodPotato-NET4.exe'" \
      "fetch 'https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe' '$privesc/GodPotato-NET4.exe'"
  # winPEAS — Windows local privesc enumeration (PowerShell form). The .ps1 is
  # NOT published as a release asset (that URL 404s); pull it from the repo
  # source, with a jsDelivr CDN mirror as the alternate method.
  install_tool "winPEAS.ps1" "test -s '$privesc/winPEAS.ps1'" \
      "fetch 'https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1' '$privesc/winPEAS.ps1'" \
      "fetch 'https://cdn.jsdelivr.net/gh/peass-ng/PEASS-ng@master/winPEAS/winPEASps1/winPEAS.ps1' '$privesc/winPEAS.ps1'"
  # PowerUp — PowerShell privesc checks (misconfig hunting).
  install_tool "PowerUp.ps1" "test -s '$privesc/PowerUp.ps1'" \
      "fetch 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1' '$privesc/PowerUp.ps1'"

  # ---- enum/ : on-host AD enumeration ----
  # PowerView — the AD domain enumeration workhorse.
  install_tool "PowerView.ps1" "test -s '$enum/PowerView.ps1'" \
      "fetch 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' '$enum/PowerView.ps1'"
  # Powermad — machine account (MAQ) abuse, e.g. for RBCD attacks.
  install_tool "Powermad.ps1" "test -s '$enum/Powermad.ps1'" \
      "fetch 'https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1' '$enum/Powermad.ps1'"

  # ---- creds/ & persistence/ : STEALTH-gated ----
  if [[ "$STEALTH" -eq 1 ]]; then
    log INFO "STEALTH mode ON — skipping Mimikatz + Rubeus staging"
    record "Mimikatz" SKIP "stealth mode — not staged"
    record "Rubeus.exe" SKIP "stealth mode — not staged"
    note "STEALTH: Mimikatz NOT staged. Dump creds Kali-side with impacket secretsdump.py (no binary touches the target)."
    note "STEALTH: Rubeus NOT staged. Do ticket ops Kali-side with impacket getTGT.py / GetUserSPNs.py instead of Rubeus."
  else
    # Mimikatz — credential dumping (LSASS, DPAPI, tickets). Both EXE + PS1 form.
    install_tool "Mimikatz" "test -s '$creds/mimikatz.exe'" "stage_mimikatz_exe '$creds'"
    install_tool "Invoke-Mimikatz.ps1" "test -s '$creds/Invoke-Mimikatz.ps1'" \
        "fetch 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1' '$creds/Invoke-Mimikatz.ps1'"
    # Rubeus — Kerberos abuse toolkit (roasting, S4U, PTT, ticket extraction).
    install_tool "Rubeus.exe" "test -s '$persist/Rubeus.exe'" \
        "fetch 'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe' '$persist/Rubeus.exe'"
    note "STAGED mode: Mimikatz ($creds/) + Rubeus ($persist/) ready to deliver to Windows targets."
  fi
}

# Mimikatz release is a zip; extract the x64 exe into creds/.
stage_mimikatz_exe() {      # stage_mimikatz_exe <dest-dir>
  local dest="$1"
  local zip="$TMPD/mimikatz_trunk.zip"
  fetch "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" "$zip" || return 1
  rm -rf "$TMPD/mimikatz"; mkdir -p "$TMPD/mimikatz"
  unzip -o "$zip" -d "$TMPD/mimikatz" >>"$LOGFILE" 2>&1 || return 1
  # Prefer the x64 build.
  local src
  src="$(find "$TMPD/mimikatz" -iname 'mimikatz.exe' -path '*x64*' | head -n1)"
  [[ -z "$src" ]] && src="$(find "$TMPD/mimikatz" -iname 'mimikatz.exe' | head -n1)"
  [[ -z "$src" ]] && return 1
  cp "$src" "$dest/mimikatz.exe"
}

# =============================================================================
#  SECTION: wordlists
# =============================================================================
sec_wordlists() {
  log INFO "########## SECTION: wordlists ##########"

  # SecLists — the catch-all collection (usernames, passwords, discovery, etc.).
  install_tool "seclists"      "test -d /usr/share/seclists && ls /usr/share/seclists | grep -q ." \
      "apt_install seclists"

  # rockyou.txt — the staple password list; gunzip it if still compressed.
  log INFO "=== ${C_BOLD}rockyou.txt${C_RESET} ==="
  if [[ -s /usr/share/wordlists/rockyou.txt ]]; then
    log SKIP "rockyou.txt already decompressed"
    record "rockyou.txt" SKIP "already present"
  elif [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
    if $SUDO gunzip -k /usr/share/wordlists/rockyou.txt.gz >>"$LOGFILE" 2>&1 && [[ -s /usr/share/wordlists/rockyou.txt ]]; then
      log OK "rockyou.txt decompressed"
      record "rockyou.txt" PASS "gunzipped from .gz"
    else
      log ERROR "rockyou.txt: gunzip failed"
      record "rockyou.txt" FAIL "gunzip failed"
    fi
  else
    # Not present at all — pull it via the wordlists package.
    if apt_install wordlists && { [[ -s /usr/share/wordlists/rockyou.txt ]] || { [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && $SUDO gunzip -k /usr/share/wordlists/rockyou.txt.gz >>"$LOGFILE" 2>&1; }; } && [[ -s /usr/share/wordlists/rockyou.txt ]]; then
      log OK "rockyou.txt installed & decompressed"
      record "rockyou.txt" PASS "via wordlists pkg"
    else
      log ERROR "rockyou.txt not found and could not be installed"
      record "rockyou.txt" FAIL "not found"
    fi
  fi

  # hashcat rules — confirm the rules directory is populated (used for cracking).
  log INFO "=== ${C_BOLD}hashcat rules${C_RESET} ==="
  if ls /usr/share/hashcat/rules/ 2>/dev/null | grep -q .; then
    log OK "/usr/share/hashcat/rules/ is populated"
    record "hashcat-rules" PASS "/usr/share/hashcat/rules/ populated"
  else
    log WARN "/usr/share/hashcat/rules/ missing or empty — trying to (re)install hashcat"
    if apt_install hashcat && ls /usr/share/hashcat/rules/ 2>/dev/null | grep -q .; then
      log OK "hashcat rules populated after reinstall"
      record "hashcat-rules" PASS "populated after hashcat (re)install"
    else
      log ERROR "hashcat rules still missing"
      record "hashcat-rules" FAIL "rules dir empty"
    fi
  fi
}

# =============================================================================
#  SECTION: domain-level persistence (proof-of-concept depth)
#
#  No separate packages — both techniques ride on tools installed above. This
#  section just confirms reachability and flags readiness in the summary.
# =============================================================================
sec_persistence() {
  log INFO "########## SECTION: domain-level persistence ##########"

  # Golden Ticket forging via impacket ticketer.py.
  log INFO "=== ${C_BOLD}Golden Ticket (ticketer)${C_RESET} ==="
  if has_cmd_any impacket-ticketer ticketer.py; then
    log OK "impacket ticketer reachable"
    record "ticketer (Golden Ticket)" PASS "reachable"
    note "PERSISTENCE: Golden Ticket forging ready via impacket ticketer.py (needs krbtgt hash + domain SID from secretsdump/DCSync)."
  else
    log ERROR "ticketer not reachable — ensure impacket installed (AD section)"
    record "ticketer (Golden Ticket)" FAIL "not reachable (run ad section)"
  fi

  # AD CS-based persistence via certipy-ad.
  log INFO "=== ${C_BOLD}AD CS persistence (certipy)${C_RESET} ==="
  if has_cmd_any certipy; then
    log OK "certipy reachable"
    record "certipy (AD CS persist)" PASS "reachable"
    note "PERSISTENCE: AD CS-based persistence ready via certipy-ad (e.g. forge/enroll certs for long-lived auth; 'certipy ca'/'certipy req')."
  else
    log ERROR "certipy not reachable — ensure certipy-ad installed (AD section)"
    record "certipy (AD CS persist)" FAIL "not reachable (run ad section)"
  fi
}

# =============================================================================
#  Final verification summary
# =============================================================================
print_summary() {
  local pass=0 fail=0 skip=0 name status
  echo
  echo "${C_BOLD}=============================================================${C_RESET}"
  echo "${C_BOLD}  CPTC AD SETUP — VERIFICATION SUMMARY${C_RESET}"
  echo "${C_BOLD}=============================================================${C_RESET}"
  printf "  %-26s %-7s %s\n" "TOOL" "STATUS" "DETAIL"
  printf "  %-26s %-7s %s\n" "--------------------------" "------" "----------------------------------"
  {
    echo "============================================================="
    echo "  CPTC AD SETUP — VERIFICATION SUMMARY ($(date '+%Y-%m-%d %H:%M:%S'))"
    echo "============================================================="
    printf "  %-26s %-7s %s\n" "TOOL" "STATUS" "DETAIL"
  } >>"$LOGFILE"

  for name in "${TOOL_ORDER[@]}"; do
    status="${RESULTS[$name]}"
    local color="$C_RESET"
    case "$status" in
      PASS) color="$C_GRN"; pass=$((pass+1)) ;;
      SKIP) color="$C_CYN"; skip=$((skip+1)) ;;
      FAIL) color="$C_RED"; fail=$((fail+1)) ;;
    esac
    printf "  %-26s ${color}%-7s${C_RESET} %s\n" "$name" "$status" "${RESULT_NOTE[$name]}"
    printf "  %-26s %-7s %s\n" "$name" "$status" "${RESULT_NOTE[$name]}" >>"$LOGFILE"
  done

  echo "${C_BOLD}-------------------------------------------------------------${C_RESET}"
  echo "  ${C_GRN}PASS: $pass${C_RESET}   ${C_CYN}SKIP: $skip${C_RESET}   ${C_RED}FAIL: $fail${C_RESET}   (STEALTH: $([[ $STEALTH -eq 1 ]] && echo ON || echo OFF))"
  echo "  Totals -> PASS:$pass SKIP:$skip FAIL:$fail  (STEALTH $([[ $STEALTH -eq 1 ]] && echo ON || echo OFF))" >>"$LOGFILE"

  if (( ${#NOTES[@]} > 0 )); then
    echo
    echo "${C_BOLD}  ATTACK-CHAIN READINESS NOTES${C_RESET}"
    echo "  ----------------------------"
    local n
    for n in "${NOTES[@]}"; do
      echo "   * $n"
      echo "   * $n" >>"$LOGFILE"
    done
  fi

  echo
  echo "  Full log: ${C_BOLD}$LOGFILE${C_RESET}"
  if (( fail > 0 )); then
    echo "  ${C_RED}${C_BOLD}>> $fail tool(s) need manual attention before the clock starts. <<${C_RESET}"
  else
    echo "  ${C_GRN}${C_BOLD}>> All sections green — ready. <<${C_RESET}"
  fi
}

# =============================================================================
#  Dispatcher / CLI
# =============================================================================
ALL_SECTIONS=(prep recon ad coercion creds payloads wordlists persistence)

run_section() {
  case "$1" in
    prep|system|base)        sec_prep ;;
    recon|enum)              sec_recon ;;
    ad|exploit|adexploit)    sec_ad ;;
    coercion|relay|ntlm)     sec_coercion ;;
    creds|credhunt|snaffler) sec_creds ;;
    payloads|windows|win)    sec_payloads ;;
    wordlists|lists)         sec_wordlists ;;
    persistence|persist)     sec_persistence ;;
    *) log ERROR "Unknown section: $1"; return 1 ;;
  esac
}

usage() {
  cat <<EOF
CPTC — Windows/AD attack-chain Kali setup

Usage:
  $0 [--stealth] [--no-color] [SECTION ...]
  $0 [--stealth] --section SECTION [--section SECTION ...]
  $0 --list
  $0 --help

Options:
  --stealth        Skip staging Mimikatz + Rubeus; summary notes the Kali-side
                   Impacket alternatives instead. (Single toggle, both tools.)
  --section NAME   Run a specific section (repeatable).
  --no-color       Disable coloured output.
  --list           List section names and exit.
  --help           Show this help.

Sections (run in this order when none are specified):
  prep         base/session tooling + docker (for BloodHound CE)
  recon        nmap, AutoRecon, netexec, smb tools, enum4linux-ng, kerbrute,
               ldapdomaindump, BloodHound CE (+legacy fallback), bloodhound-python
  ad           impacket (isolated), certipy-ad, bloodyad, gpp-decrypt,
               hashcat/john/hashid, evil-winrm
  coercion     PetitPotam, krbrelayx (incl. printerbug.py)
  creds        Snaffler
  payloads     Windows payloads under ~/tools/windows-payloads/ (STEALTH-gated
               for Mimikatz + Rubeus)
  wordlists    seclists, rockyou.txt, hashcat rules
  persistence  confirm Golden Ticket (ticketer.py) + AD CS (certipy) readiness

Re-run any single section safely after a partial failure, e.g.:
  $0 recon
EOF
}

main() {
  local sections=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --stealth)   STEALTH=1 ;;
      --no-color)  C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_BOLD="" ;;
      --section)   shift; [[ -n "$1" ]] && sections+=("$1") ;;
      --list)      printf '%s\n' "${ALL_SECTIONS[@]}"; exit 0 ;;
      -h|--help)   usage; exit 0 ;;
      --*)         echo "Unknown option: $1" >&2; usage; exit 2 ;;
      *)           sections+=("$1") ;;
    esac
    shift
  done

  mkdir -p "$LOG_DIR" "$TOOLS_DIR"
  : >"$LOGFILE"
  log INFO "CPTC AD setup starting — log: $LOGFILE"
  log INFO "Mode: $([[ $STEALTH -eq 1 ]] && echo STEALTH || echo STAGED)   User: $(id -un)   Sudo: ${SUDO:-none}"

  if (( ${#sections[@]} == 0 )); then
    sections=("${ALL_SECTIONS[@]}")
    log INFO "No section specified — running all sections."
  fi

  local s
  for s in "${sections[@]}"; do
    run_section "$s" || log WARN "Section '$s' reported a problem (continuing)."
  done

  print_summary
}

main "$@"
