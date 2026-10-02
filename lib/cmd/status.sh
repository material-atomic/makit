# shellcheck shell=bash
cmd_status() {
  [[ ${1:-} == --help ]] && { echo "makit status — read-only summary of what makit manages."; return; }
  require_supported_os
  printf '%smakit %s%s on %s (%s)\n' "$C_B" "$MAKIT_VERSION" "$C_0" "$OS_NAME" "$ARCH"
  printf '  RAM      %s MiB, swap %s MiB\n' "$(mem_mb)" "$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)"
  df -h -x tmpfs -x devtmpfs -x overlay -x squashfs --output=target,size,used,pcent 2>/dev/null | sed 's/^/  /'
  if have docker; then printf '  docker   %s\n' "$(docker --version 2>/dev/null)"; else printf '  docker   not installed\n'; fi
  if have ufw; then printf '  ufw      %s\n' "$(ufw status 2>/dev/null | head -1 | sed 's/Status: //')"; fi
  local pa=''; have sshd && pa=$(sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" {print $2}' || true)
  if have sshd; then printf '  ssh      password login: %s\n' "${pa:-unknown (run as root)}"; else printf '  ssh      no OpenSSH server\n'; fi
  [[ -f $SYSCTL_FILE ]] && sed 's/^/  sysctl   /' "$SYSCTL_FILE"
  findmnt -rn /var/lib/docker/volumes >/dev/null 2>&1 && printf '  volumes  /var/lib/docker/volumes is on %s\n' "$(findmnt -rno SOURCE /var/lib/docker/volumes)"
  [[ -f /var/run/reboot-required ]] && warn "reboot required (kernel or libc update)"
  return 0
}
