# shellcheck shell=bash
FIREWALL_DEFAULT=(22/tcp 80/tcp 443/tcp 443/udp)

# Ports sshd listens on: never lock out a non-standard SSH port.
ssh_ports() { have sshd || return 0; sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u || true; }

cmd_firewall() {
  [[ ${1:-} == --help ]] && { echo "makit firewall [PORT/PROTO…] — deny incoming except the given ports (default: ${FIREWALL_DEFAULT[*]}) plus every port sshd listens on. Existing rules are kept."; return; }
  require_root
  step "Firewall (ufw)"
  have ufw || apt_install ufw
  local rules=("$@") p
  [[ ${#rules[@]} -gt 0 ]] || rules=("${FIREWALL_DEFAULT[@]}")
  for p in $(ssh_ports); do rules+=("$p/tcp"); done
  run ufw default deny incoming >/dev/null
  run ufw default allow outgoing >/dev/null
  local seen=" "
  for p in "${rules[@]}"; do
    [[ $p =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]] || die "Bad port rule: $p (use 443/tcp, 443/udp, 6000:6010/tcp)"
    [[ $seen == *" $p "* ]] && continue; seen+="$p "
    run ufw allow "$p" >/dev/null
    info "allow $p"
  done
  run ufw --force enable >/dev/null
  ok "ufw enabled"
  warn "Docker-published ports bypass ufw: bind internal services to 127.0.0.1 in compose (\"127.0.0.1:5432:5432\")."
}
