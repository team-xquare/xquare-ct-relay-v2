#!/usr/bin/env bash
set -euo pipefail

# Xquare CT Relay target VM helper
# Paste-and-run:
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/team-xquare/xquare-ct-relay-v2/main/scripts/enable-ssh-password-auth.sh)"
# or just: sudo bash scripts/enable-ssh-password-auth.sh

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[error] run as root: sudo bash $0" >&2
  exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DIR="/etc/ssh/sshd_config.d"
BACKUP_DIR="/var/backups/xquare-ct-relay"
TS="$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR" /etc/ssh
touch "$SSHD_CONFIG"

cp -a "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.$TS.bak"
if [[ -d "$SSHD_DIR" ]]; then
  while IFS= read -r -d '' f; do
    cp -a "$f" "$BACKUP_DIR/$(basename "$f").$TS.bak"
  done < <(find "$SSHD_DIR" -maxdepth 1 -type f -print0 2>/dev/null || true)
fi
echo "[ok] backups: $BACKUP_DIR"

set_kv() {
  local file="$1" key="$2" value="$3"
  local tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN{done=0; re="^[#[:space:]]*"key"[[:space:]]+"}
    $0 ~ re {
      if (done==0) { print key " " value; done=1 }
      else { print "# " $0 " # managed-by-xquare-ct-relay" }
      next
    }
    { print }
    END { if (done==0) print key " " value }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

# Main sshd config
set_kv "$SSHD_CONFIG" "PasswordAuthentication" "yes"
set_kv "$SSHD_CONFIG" "KbdInteractiveAuthentication" "yes"
set_kv "$SSHD_CONFIG" "ChallengeResponseAuthentication" "yes"
set_kv "$SSHD_CONFIG" "UsePAM" "yes"
set_kv "$SSHD_CONFIG" "PermitRootLogin" "yes"

# Override common Ubuntu/cloud-init drop-ins
if [[ -d "$SSHD_DIR" ]]; then
  for f in "$SSHD_DIR"/*.conf; do
    [[ -e "$f" ]] || continue
    if grep -Eqi '^[#[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication)[[:space:]]+' "$f"; then
      set_kv "$f" "PasswordAuthentication" "yes"
      set_kv "$f" "KbdInteractiveAuthentication" "yes"
      set_kv "$f" "ChallengeResponseAuthentication" "yes"
      echo "[ok] updated: $f"
    fi
  done
  if [[ -f "$SSHD_DIR/60-cloudimg-settings.conf" ]]; then
    set_kv "$SSHD_DIR/60-cloudimg-settings.conf" "PasswordAuthentication" "yes"
  fi
fi

# cloud.cfg best effort
if [[ -f /etc/cloud/cloud.cfg ]] && grep -Eq '^[[:space:]]*ssh_pwauth:' /etc/cloud/cloud.cfg; then
  sed -i 's/^[[:space:]]*ssh_pwauth:.*/ssh_pwauth: true/' /etc/cloud/cloud.cfg || true
  echo "[ok] updated /etc/cloud/cloud.cfg"
fi

SSHD_BIN="$(command -v sshd || true)"
[[ -z "$SSHD_BIN" && -x /usr/sbin/sshd ]] && SSHD_BIN="/usr/sbin/sshd"
if [[ -n "$SSHD_BIN" ]]; then
  "$SSHD_BIN" -t
  echo "[ok] sshd config test passed"
else
  echo "[warn] sshd not found, skipped config test"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
elif command -v service >/dev/null 2>&1; then
  service ssh restart 2>/dev/null || service sshd restart
else
  echo "[error] could not restart ssh service" >&2
  exit 1
fi
echo "[ok] ssh restarted"

echo
echo "=== Effective settings ==="
if [[ -n "$SSHD_BIN" ]]; then
  "$SSHD_BIN" -T 2>/dev/null | egrep '^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|permitrootlogin|usepam|port) ' || true
fi

cat <<'MSG'

[done] SSH password auth enabled.
If needed, set password:
  sudo passwd ubuntu
  sudo passwd root
MSG
