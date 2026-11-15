#!/bin/bash
# proxy-guard: keep the macOS system proxy pointed at FlClash (127.0.0.1:7890)
# whenever FlClash's port is live. If 7890 is not listening, do nothing, so a
# deliberate FlClash shutdown is respected (never point the system at a dead
# proxy). Installed 2026-11-08 at the owner's request after a company->home
# network switch left the system proxy toggles off and broke the Muse app
# and Codex.
LOG="$HOME/proxy-guard.log"
HOSTIP=127.0.0.1
PORT=7890

ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Is anything listening on the FlClash port?
if ! /usr/bin/nc -z -G 2 "$HOSTIP" "$PORT" 2>/dev/null; then
  exit 0
fi

# Find the network service that owns the default-route interface.
DEV=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
[ -z "$DEV" ] && exit 0
SVC=$(networksetup -listallhardwareports | awk -v dev="$DEV" '
  /^Hardware Port:/ { hp=$0; sub(/^Hardware Port: /,"",hp) }
  /^Device:/ { if ($2==dev) { print hp; exit } }')
[ -z "$SVC" ] && exit 0

changed=0
for kind in web secureweb socksfirewall; do
  state=$(networksetup -get${kind}proxy "$SVC" 2>/dev/null)
  enabled=$(printf '%s\n' "$state" | awk -F': ' '/^Enabled:/{print $2}')
  server=$(printf '%s\n' "$state" | awk -F': ' '/^Server:/{print $2}')
  port=$(printf '%s\n' "$state" | awk -F': ' '/^Port:/{print $2}')
  if [ "$server" != "$HOSTIP" ] || [ "$port" != "$PORT" ]; then
    networksetup -set${kind}proxy "$SVC" "$HOSTIP" "$PORT" 2>/dev/null && changed=1
  fi
  if [ "$enabled" != "Yes" ]; then
    networksetup -set${kind}proxystate "$SVC" on 2>/dev/null && changed=1
  fi
done

if [ "$changed" = 1 ]; then
  echo "$(ts) proxy-guard: re-enabled system proxy on service '$SVC' ($DEV) -> $HOSTIP:$PORT" >> "$LOG"
fi
exit 0
