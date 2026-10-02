# shellcheck shell=bash
cmd_system_upgrade() {
  local full=0 autoremove=0 a
  for a in "$@"; do
    case "$a" in
      --help) echo "makit system-upgrade [--full] [--autoremove] — apt-get update + upgrade (non-interactive, keeps changed config files).
  --full        dist-upgrade: also installs/removes packages to complete upgrades (new kernels)
  --autoremove  remove packages no longer needed afterwards"; return ;;
      --full) full=1 ;;
      --autoremove) autoremove=1 ;;
      *) die "Unknown option: $a" ;;
    esac
  done
  require_root; require_supported_os
  step "Package upgrade"
  local opts=(-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
  run apt-get update -qq
  if [[ $full -eq 1 ]]; then run env DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade "${opts[@]}"
  else run env DEBIAN_FRONTEND=noninteractive apt-get upgrade "${opts[@]}"; fi
  [[ $autoremove -eq 1 ]] && run env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq
  ok "packages up to date"
  if [[ -f /var/run/reboot-required ]]; then
    warn "reboot required: $(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null || true)"
  fi
}
