#!/usr/bin/env bash
# =============================================================================
#  add_cred.sh  —  manually add a credential to creds.json  (ATOMIC)
# =============================================================================
#  Attack-chain role: record a credential obtained OUTSIDE the toolkit (from a
#  teammate, phishing, found some other way) so the rest of the scripts can use
#  it. Writes through the same creds_add helper as every other script, so the
#  entry (schema, dedupe, redaction tracking) is identical.
#
#  Provide values via flags; anything omitted is prompted for interactively.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat <<EOF
add_cred.sh — manually add a credential to creds.json (no pausing)

Flags (any omitted value is prompted for):
  -d, --domain <domain>       domain for the cred (e.g. support.htb)
  -u, --username <user>       account name
  -s, --secret-type <type>    one of: password | ntlm_hash | aes_key
  -x, --secret-value <value>  the password / NT hash / AES key
  -o, --obtained-via <note>   how it was found (default: "manually added")
  -h, --help                  this help

Example:
  ./add_cred.sh -d support.htb -u ldap -s password -x ' Railway!' -o 'found in LDAP info field'
  ./add_cred.sh                      # fully interactive

Prereqs: none (creds.json is created if absent). jq required (already on Kali).
EOF
}

USERNAME="" STYPE="" SVALUE="" VIA="manually added"

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--username)      USERNAME="$2"; shift 2 ;;
    -s|--secret-type)   STYPE="$2"; shift 2 ;;
    -x|--secret-value)  SVALUE="$2"; shift 2 ;;
    -o|--obtained-via)  VIA="$2"; shift 2 ;;
    -h|--help)          usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

# Domain: -d/--domain, else domain.env, else prompt (one-off).
DOMAIN="$(resolve_domain)"
[[ -z "$DOMAIN" ]] && { printf 'domain: ' >&2; read -r DOMAIN </dev/tty || true; }

# Prompt for anything still missing.
[[ -z "$USERNAME" ]] && { printf 'username: ' >&2; read -r USERNAME </dev/tty || true; }
while [[ "$STYPE" != "password" && "$STYPE" != "ntlm_hash" && "$STYPE" != "aes_key" ]]; do
  printf 'secret_type [password|ntlm_hash|aes_key]: ' >&2
  read -r STYPE </dev/tty || { STYPE=""; break; }
done
[[ -z "$SVALUE" ]] && { printf 'secret_value: ' >&2; read -r SVALUE </dev/tty || true; }

# Track the secret before the first log write so it is redacted in the header.
secret_track "$SVALUE"
log_begin

# Validate and store via the shared helper (dedupes + tracks for redaction).
[[ -n "$DOMAIN"   ]] || die "domain is required"
[[ -n "$USERNAME" ]] || die "username is required"
[[ -n "$SVALUE"   ]] || die "secret_value is required"
case "$STYPE" in
  password|ntlm_hash|aes_key) : ;;
  *) die "secret_type must be password | ntlm_hash | aes_key (got '${STYPE}')" ;;
esac

if creds_add "$DOMAIN" "$USERNAME" "$STYPE" "$SVALUE" "$VIA"; then
  log_ok "added ${DOMAIN}/${USERNAME} (${STYPE}) to ${CREDS_FILE}"
  log_end "success"
else
  log_end "failure"; exit 1
fi
