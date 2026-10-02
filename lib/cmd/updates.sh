# shellcheck shell=bash
cmd_updates() {
  [[ ${1:-} == --help ]] && { echo "makit updates — enable unattended security upgrades (no automatic reboot)."; return; }
  require_root
  step "Automatic security updates"
  have unattended-upgrade || apt_install unattended-upgrades
  write_file /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CONF
  ok "unattended-upgrades enabled (reboots stay manual: check /var/run/reboot-required)"
}
