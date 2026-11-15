#!/bin/bash
# GUEST-FIX2: Lima rewrites /etc/environment at every boot from /mnt/lima-cidata/etc_environment,
# which carries the host proxy variables. pam_env then exports them into every login session and
# pam_systemd imports them into the user manager. Keep only non-proxy assignments here.
set -eu
f=/etc/environment
[ -f "$f" ] || exit 0
tmp=$(mktemp)
grep -viE '^[[:space:]]*[A-Za-z_]*proxy[A-Za-z_]*[[:space:]]*=' "$f" | grep -vE '^#LIMA-(START|END)[[:space:]]*$' > "$tmp" || true
if ! cmp -s "$f" "$tmp"; then
  cat "$tmp" > "$f"
  chmod 0644 "$f"
fi
rm -f "$tmp"
