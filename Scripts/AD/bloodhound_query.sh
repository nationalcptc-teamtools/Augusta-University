#!/usr/bin/env bash
# =============================================================================
#  bloodhound_query.sh  —  high-value Cypher queries against BloodHound CE (ATOMIC)
# =============================================================================
#  Attack-chain role: mine the data already collected (03_enum_creds.sh) for the
#  attack paths that matter, via the BloodHound CE REST API. Read-only: it only
#  queries existing data, runs no collection and causes no side effects — so no
#  pausing, even though it runs several queries (treated as one atomic action).
#
#  Predefined queries: shortest paths to Domain Admins, Kerberoastable users,
#  AS-REP roastable users, unconstrained delegation, DCSync-capable principals.
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SCRIPT_ARGS="$*"
source "$SCRIPT_DIR/lib/common.sh"

usage() { cat <<'EOF'
bloodhound_query.sh — predefined Cypher queries vs BloodHound CE API (ATOMIC, read-only)

USAGE:   ./bloodhound_query.sh [--bh-url URL] [--bh-user U] [--bh-pass P] [--queries a,b,c]
EXAMPLE: ./bloodhound_query.sh --bh-pass 'Adm1nPass'
         ./bloodhound_query.sh --queries kerberoastable,dcsync

FLAGS:
  --bh-url <url>    BloodHound CE base URL (default http://localhost:8080)
  --bh-user <user>  API username (default admin)
  --bh-pass <pass>  API password (or env BH_PASS; prompted if neither given)
  --queries <list>  comma-separated subset to run (default: all)
                    keys: da_paths kerberoastable asreproastable unconstrained dcsync
  -h, --help        this help
  (shared flags -q: --help-common)

WHAT IT DOES: logs in to the CE API, runs each selected Cypher query against the
  ALREADY-collected data, saves each result JSON to the loot dir, and prints a
  short summary. No collection, no exploitation.
PREREQS: BloodHound CE running with data imported (see 03_enum_creds.sh); curl + jq.
EOF
}

BH_URL="http://localhost:8080" BH_USER="admin" BH_PASS="${BH_PASS:-}" QSEL=""

parse_common_args "$@"
set -- "${COMMON_REMAINING[@]}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bh-url) BH_URL="$2"; shift 2 ;;
    --bh-user) BH_USER="$2"; shift 2 ;;
    --bh-pass) BH_PASS="$2"; shift 2 ;;
    --queries) QSEL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) log_warn "ignoring unknown arg: $1"; shift ;;
  esac
done

need_cmd curl; need_cmd jq
[[ -n "$BH_PASS" ]] || { printf 'BloodHound CE password for %s: ' "$BH_USER" >&2; read -r BH_PASS </dev/tty || true; }
[[ -n "$BH_PASS" ]] || die "no BloodHound password (pass --bh-pass or set BH_PASS)"
secret_track "$BH_PASS"

# Predefined high-value queries (BloodHound CE / Neo4j openCypher).
declare -A Q
Q[da_paths]='MATCH p=shortestPath((n)-[*1..]->(g:Group)) WHERE g.objectid ENDS WITH "-512" AND n<>g RETURN p LIMIT 25'
Q[kerberoastable]='MATCH (u:User) WHERE u.hasspn=true RETURN u.name'
Q[asreproastable]='MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name'
Q[unconstrained]='MATCH (c) WHERE c.unconstraineddelegation=true RETURN c.name'
Q[dcsync]='MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(:Domain) RETURN DISTINCT n.name'
ORDER=(da_paths kerberoastable asreproastable unconstrained dcsync)

# Selected subset (default all).
declare -a RUN=()
if [[ -n "$QSEL" ]]; then
  IFS=',' read -r -a want <<<"$QSEL"
  for k in "${want[@]}"; do
    k="$(printf '%s' "$k" | tr -d '[:space:]')"
    [[ -n "${Q[$k]:-}" ]] && RUN+=("$k") || log_warn "unknown query key: $k (skipped)"
  done
else
  RUN=("${ORDER[@]}")
fi
[[ "${#RUN[@]}" -gt 0 ]] || die "no valid queries selected"

log_begin
announce_loot
log_info "querying BloodHound CE at ${BH_URL} (${#RUN[@]} query/queries)"

# --- Authenticate (keep the password out of any logged command) -----------
LOGIN_BODY="$(loot_dir)/.bh-login.json"
jq -nc --arg u "$BH_USER" --arg s "$BH_PASS" '{login_method:"secret", username:$u, secret:$s}' > "$LOGIN_BODY"
chmod 600 "$LOGIN_BODY" 2>/dev/null
LOGIN_CMD="curl -s -X POST '${BH_URL}/api/v2/login' -H 'Content-Type: application/json' --data @'${LOGIN_BODY}'"
log_run "$LOGIN_CMD"; exec_capture "$LOGIN_CMD"
rm -f "$LOGIN_BODY"
TOKEN="$(printf '%s' "$LAST_OUTPUT" | jq -r '.data.session_token // empty' 2>/dev/null)"
if [[ -z "$TOKEN" ]]; then
  log_output
  die "BloodHound login failed (check --bh-url/--bh-user/--bh-pass and that CE is up). No token returned."
fi
secret_track "$TOKEN"                 # redact the session token from the log
master_raw "  [+] authenticated to BloodHound CE (token acquired)"

# --- Run each query -------------------------------------------------------
for key in "${RUN[@]}"; do
  cypher="${Q[$key]}"
  body="$(jq -nc --arg q "$cypher" '{query:$q, include_properties:true}')"
  out="$(loot_dir)/bh-${key}.json"
  CY_CMD="curl -s -X POST '${BH_URL}/api/v2/graphs/cypher' -H 'Authorization: Bearer ${TOKEN}' -H 'Content-Type: application/json' -d $(printf '%q' "$body")"
  log_run "$CY_CMD"; exec_capture "$CY_CMD"
  printf '%s' "$LAST_OUTPUT" > "$out"
  # Summarize: node count + up to 15 names; CE returns .data.nodes as an object.
  n="$(printf '%s' "$LAST_OUTPUT" | jq -r '(.data.nodes // {}) | length' 2>/dev/null || echo '?')"
  if [[ "$n" == "0" || -z "$n" ]]; then
    log_warn "${key}: no results (or query unsupported on this dataset) → ${out}"
  else
    log_ok "${key}: ${n} node(s) → ${out}"
    printf '%s' "$LAST_OUTPUT" | jq -r '(.data.nodes // {}) | to_entries | .[].value.label // empty' 2>/dev/null | head -n 15 | sed 's/^/      - /' >&2
  fi
  master_raw "  [query:${key}] ${n} node(s) → ${out}"
done

log_ok "BloodHound query results saved under $(loot_dir)"
log_end "success"
