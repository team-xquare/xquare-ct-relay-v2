#!/usr/bin/env bash
set -euo pipefail

# Enable SSH password authentication for xquare-ct-relay target VMs.
#
# Usage:
#   sudo bash scripts/enable-ssh-password-auth.sh [options]
#
# Options:
#   --user <name>                 Set password for this user via passwd (optional)
#   --permit-root-login <value>   yes|no|prohibit-password (default: yes)
#   --port <port>                 SSH port to ensure configured (default: 22)
#   -h, --help                    Show help
#
# Notes:
# - Run as root on the TARGET VM.
# - Backs up sshd config before editing.
# - Handles sshd_config.d / cloud-init overrides where possible.

usage() {
  sed -n '1,30p' "$0" | sed 's/^# \{0,1\}//'
}

TARGET_USER=""
PERMIT_ROOT_LOGIN="yes"
SSH_PORT="22"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) TARGET_USER="${2:-}"; shift 2 ;;
    --permit-root-login) PERMIT_ROOT_LOGIN="${2:-}"; shift 2 ;;
    --port) SSH_PORT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0 ..." >&2
  exit 1
fi

case "$PERMIT_ROOT_LOGIN" in
  yes|no|prohibit-password) ;;
  *) echo "--permit-root-login must be yes|no|prohibit-password" >&2; exit 1 ;;
esac

if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
  echo "Invalid --port: $SSH_PORT" >&2
  exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DIR="/etc/ssh/sshd_config.d"
BACKUP_DIR="/var/backups/xquare-ct-relay"
TS="$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [[ -f "$SSHD_CONFIG" ]]; then
  cp -a "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.$TS.bak"
  echo "[ok] backup: $BACKUP_DIR/sshd_config.$TS.bak"
fi

# Backup drop-in configs that may override PasswordAuthentication
if [[ -d "$SSHD_DIR" ]]; then
  while IFS= read -r -d '' f; do
    cp -a "$f" "$BACKUP_DIR/$(basename "$f").$TS.bak"
  done < <(find "$SSHD_DIR" -maxdepth 1 -type f -print0)
fi

# Ensure sshd_config exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
  mkdir -p /etc/ssh
  touch "$SSHD_CONFIG"
fi

set_kv() {
  local file="$1" key="$2" value="$3"
  local tmp
  tmp="$(mktemp)"
  if grep -Eq "^[#[:space:]]*${key}[[:space:]]+" "$file"; then
    # Replace first active/commented occurrence; comment out later duplicates of same key
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
  else
    cat "$file" > "$tmp"
    printf '\n%s %s\n' "$key" "$value" >> "$tmp"
  fi
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

# Main config
set_kv "$SSHD_CONFIG" "PasswordAuthentication" "yes"
set_kv "$SSHD_CONFIG" "KbdInteractiveAuthentication" "yes"
set_kv "$SSHD_CONFIG" "ChallengeResponseAuthentication" "yes"
set_kv "$SSHD_CONFIG" "UsePAM" "yes"
set_kv "$SSHD_CONFIG" "PermitRootLogin" "$PERMIT_ROOT_LOGIN"
set_kv "$SSHD_CONFIG" "Port" "$SSH_PORT"

# Cloud-init and drop-ins often override PasswordAuthentication on Ubuntu.
if [[ -d "$SSHD_DIR" ]]; then
  for f in "$SSHD_DIR"/*.conf; do
    [[ -e "$f" ]] || continue
    if grep -Eqi '^[#[:space:]]*PasswordAuthentication[[:space:]]+' "$f"; then
      set_kv "$f" "PasswordAuthentication" "yes"
      echo "[ok] updated override: $f"
    fi
  done
  # Common cloud-init file
  CLOUD_INIT="$SSHD_DIR/60-cloudimg-settings.conf"
  if [[ -f "$CLOUD_INIT" ]]; then
    set_kv "$CLOUD_INIT" "PasswordAuthentication" "yes"
  fi
fi

# Also handle cloud-init ssh_pwauth style config if present
if [[ -f /etc/cloud/cloud.cfg ]]; then
  if grep -Eq '^[[:space:]]*ssh_pwauth:' /etc/cloud/cloud.cfg; then
    sed -i 's/^[[:space:]]*ssh_pwauth:.*/ssh_pwauth: true/' /etc/cloud/cloud.cfg || true
    echo "[ok] updated /etc/cloud/cloud.cfg ssh_pwauth"
  fi
fi

# Validate config before restart
SSHD_BIN="$(command -v sshd || true)"
if [[ -z "$SSHD_BIN" && -x /usr/sbin/sshd ]]; then
  SSHD_BIN="/usr/sbin/sshd"
fi
if [[ -n "$SSHD_BIN" ]]; then
  if "$SSHD_BIN" -t; then
    echo "[ok] sshd config test passed"
  else
    echo "[error] sshd config test failed. Backups in $BACKUP_DIR" >&2
    exit 1
  fi
else
  echo "[warn] sshd binary not found; skipped config test"
fi

# Restart/enable SSH service (distro differences)
restart_ssh() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable ssh >/dev/null 2>&1 || true
    systemctl enable sshd >/dev/null 2>&1 || true
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
    systemctl status ssh --no-pager -l 2>/dev/null || systemctl status sshd --no-pager -l 2>/dev/null || true
    return
  fi
  if command -v service >/dev/null 2>&1; then
    service ssh restart 2>/dev/null || service sshd restart
    return
  fi
  echo "[warn] could not restart ssh service automatically" >&2
}

restart_ssh
echo "[ok] ssh service restarted"

# Optional password set
if [[ -n "$TARGET_USER" ]]; then
  if id "$TARGET_USER" >/dev/null 2>&1; then
    echo "[info] setting password for user: $TARGET_USER"
    passwd "$TARGET_USER"
  else
    echo "[error] user not found: $TARGET_USER" >&2
    exit 1
  fi
fi

# Show effective settings
echo
echo "=== Effective SSH settings ==="
if [[ -n "$SSHD_BIN" ]]; then
  "$SSHD_BIN" -T 2>/dev/null | egrep '^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|permitrootlogin|port|usepam) ' || true
fi

echo
echo "[done] Password SSH auth configured."
echo "If connecting as root, ensure you know the root password: sudo passwd root"
