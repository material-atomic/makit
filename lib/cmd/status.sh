# shellcheck shell=bash
cmd_status() {
  [[ ${1:-} == --help ]] && { echo "makit status — read-only summary of what makit manages."; return; }
  require_supported_os
  printf '%smakit %s%s on %s (%s)\n' "$C_B" "$MAKIT_VERSION" "$C_0" "$OS_NAME" "$ARCH"
  label() { printf '  %s%-8s%s ' "$C_C" "$1" "$C_0"; }
  label RAM; printf '%s MiB, swap %s MiB\n' "$(mem_mb)" "$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)"
  df -h -x tmpfs -x devtmpfs -x overlay -x squashfs --output=target,size,used,pcent 2>/dev/null |
    sed "1s/.*/  $C_D&$C_0/; 2,\$s/^/  /"
  label docker; if have docker; then docker --version 2>/dev/null; else printf '%snot installed%s\n' "$C_Y" "$C_0"; fi
  if have ufw; then
    local st; st=$(ufw status 2>/dev/null | head -1 | sed 's/Status: //' || true)
    label ufw; if [[ $st == active ]]; then printf '%s%s%s\n' "$C_G" "$st" "$C_0"; else printf '%s%s%s\n' "$C_Y" "$st" "$C_0"; fi
  fi
  local pa=''; have sshd && pa=$(sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" {print $2}' || true)
  label ssh
  if ! have sshd; then printf 'no OpenSSH server\n'
  elif [[ $pa == no ]]; then printf 'password login: %sno%s\n' "$C_G" "$C_0"
  elif [[ $pa == yes ]]; then printf 'password login: %syes%s\n' "$C_Y" "$C_0"
  else printf 'password login: %sunknown (run as root)%s\n' "$C_D" "$C_0"; fi
  [[ -f $SYSCTL_FILE ]] && sed "s/^/  ${C_C}sysctl  ${C_0} /" "$SYSCTL_FILE"
  findmnt -rn /var/lib/docker/volumes >/dev/null 2>&1 && { label volumes; printf '/var/lib/docker/volumes is on %s\n' "$(findmnt -rno SOURCE /var/lib/docker/volumes)"; }
  [[ -f /var/run/reboot-required ]] && warn "reboot required (kernel or libc update)"
  return 0
}
