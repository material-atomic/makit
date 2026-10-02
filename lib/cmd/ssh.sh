# shellcheck shell=bash
# sshd keeps the FIRST value it reads and includes sshd_config.d/*.conf in name order, so "00-" wins over
# cloud-init's 50-cloud-init.conf (which often sets PasswordAuthentication yes).
SSH_DROPIN=/etc/ssh/sshd_config.d/00-makit.conf

count_keys() { local n=0; [[ -f $1 ]] && n=$(grep -cvE '^[[:space:]]*(#|$)' "$1" || true); echo "${n:-0}"; }

cmd_ssh() {
  [[ ${1:-} == --help ]] && { echo "makit ssh — disable SSH password login (root keeps key login). Skipped when root has no authorized key, so you cannot lock yourself out."; return; }
  require_root
  step "SSH: key-only login"
  have sshd || { info "no OpenSSH server installed — nothing to do"; return 0; }
  local keys; keys=$(count_keys /root/.ssh/authorized_keys)
  if [[ $keys -eq 0 ]]; then
    warn "NOT changed: root has no key in /root/.ssh/authorized_keys — disabling passwords now would lock you out."
    info "From your computer: ssh-copy-id root@<server>   then run: makit ssh"
    return 0
  fi
  info "root has $keys authorized key(s)"
  local u home
  while IFS=: read -r u _ _ _ _ home _; do
    [[ $(count_keys "$home/.ssh/authorized_keys") -eq 0 ]] && warn "user '$u' has no SSH key and will no longer log in with a password"
  done < <(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/' /etc/passwd)
  write_file "$SSH_DROPIN" <<'CONF'
# Managed by makit: key-only SSH.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
CONF
  [[ $MAKIT_DRY -eq 1 ]] && return 0
  # Validate before reloading: a broken sshd config means no way back in.
  if ! sshd -t; then rm -f "$SSH_DROPIN"; die "sshd rejected the config — reverted, nothing changed."; fi
  systemctl reload ssh 2>/dev/null || systemctl reload sshd
  if sshd -T 2>/dev/null | grep -qx 'passwordauthentication no'; then ok "password login disabled"
  else warn "sshd still reports password login enabled — another config sets it; check: sshd -T | grep -i password"; fi
}
