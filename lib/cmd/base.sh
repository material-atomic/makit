# shellcheck shell=bash
BASE_PACKAGES=(ca-certificates curl gnupg git rsync ufw fail2ban unattended-upgrades jq)

cmd_base() {
  [[ ${1:-} == --help ]] && { echo "makit base — makit system-upgrade, then install: ${BASE_PACKAGES[*]}"; return; }
  require_root; require_supported_os
  step "System update and base packages"
  info "$OS_NAME ($ARCH)"
  cmd_system_upgrade >/dev/null
  apt_install "${BASE_PACKAGES[@]}"
  ok "base packages installed"
}
