# shellcheck shell=bash
# docs/security/firewall.md, docker-ports.md, egress.md
FIREWALL_DEFAULT=(22/tcp 80/tcp 443/tcp 443/udp)
UFW_AFTER=/etc/ufw/after.rules
PRIVATE_NETS=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)

# Ports sshd listens on: never lock out a non-standard SSH port.
ssh_ports() { have sshd || return 0; sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u || true; }

valid_port() { [[ $1 =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]] || die "Bad port rule: $1 (use 443/tcp, 443/udp, 6000:6010/tcp)"; }

cmd_firewall() {
  local rules=() docker=0 egress=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help) echo "makit firewall [PORT/PROTO…] [--docker] [--egress \"PORT/PROTO…\"|off]
  Deny incoming except the given ports (default: ${FIREWALL_DEFAULT[*]}) plus every port sshd listens on; existing rules kept.
  --docker   make ufw filter traffic to containers (DOCKER-USER), allowing the given ports (container side; SSH excluded)
  --egress   containers may open only these ports (+ DNS) to the internet; 'off' removes the policy (implies --docker)
Docs: makit docs firewall | docker-ports | egress"; return ;;
      --docker) docker=1 ;;
      --egress) egress=${2:?--egress needs ports or off}; docker=1; shift ;;
      --egress=*) egress=${1#--egress=}; docker=1 ;;
      -*) die "Unknown option: $1" ;;
      *) valid_port "$1"; rules+=("$1") ;;
    esac
    shift
  done
  require_root
  step "Firewall (ufw)"
  have ufw || apt_install ufw
  [[ ${#rules[@]} -gt 0 ]] || rules=("${FIREWALL_DEFAULT[@]}")
  local all=("${rules[@]}") p seen=" "
  for p in $(ssh_ports); do all+=("$p/tcp"); done
  run ufw default deny incoming >/dev/null
  run ufw default allow outgoing >/dev/null
  for p in "${all[@]}"; do
    [[ $seen == *" $p "* ]] && continue; seen+="$p "
    run ufw allow "$p" >/dev/null
    info "allow $p"
  done
  run ufw --force enable >/dev/null
  ok "ufw enabled"
  if [[ $docker -eq 1 ]]; then
    firewall_docker "$egress" "${rules[@]}"
  elif have docker; then
    warn "Docker-published ports bypass ufw: run 'makit firewall --docker' (makit docs docker-ports)."
  fi
}

# firewall_docker EGRESS PORTS… — writes the makit block of $UFW_AFTER and allows PORTS to containers.
firewall_docker() {
  local egress=$1; shift
  local ports=("$@") p n block
  step "Docker traffic through ufw"
  if [[ ! -f $UFW_AFTER && $MAKIT_DRY -eq 0 ]]; then die "$UFW_AFTER not found (is ufw installed?)"; fi
  # Keep the egress policy already in place unless asked to change it.
  if [[ -z $egress ]]; then egress=$(sed -n 's/^# makit egress: //p' "$UFW_AFTER" 2>/dev/null | head -1); fi
  [[ $egress == off ]] && egress=''
  local eg=()
  # shellcheck disable=SC2206 # word-splitting the port list is intended
  [[ -n $egress ]] && eg=($egress)
  for p in "${eg[@]}"; do valid_port "$p"; done

  block="# BEGIN makit docker — managed by makit firewall --docker (docs/security/docker-ports.md, egress.md)"
  [[ -n $egress ]] && block+=$'\n'"# makit egress: $egress"
  block+=$'\n'"*filter"$'\n'":DOCKER-USER - [0:0]"$'\n'":ufw-user-forward - [0:0]"
  if [[ ${#eg[@]} -gt 0 ]]; then
    block+=$'\n'":MAKIT-EGRESS - [0:0]"
    for n in "${PRIVATE_NETS[@]}"; do block+=$'\n'"-A DOCKER-USER -m conntrack --ctstate NEW -s $n -j MAKIT-EGRESS"; done
    for n in "${PRIVATE_NETS[@]}" 127.0.0.0/8 169.254.0.0/16 100.64.0.0/10; do block+=$'\n'"-A MAKIT-EGRESS -d $n -j RETURN"; done
    block+=$'\n'"-A MAKIT-EGRESS -p udp --dport 53 -j RETURN"$'\n'"-A MAKIT-EGRESS -p tcp --dport 53 -j RETURN"
    for p in "${eg[@]}"; do
      local port=${p%/*} proto=tcp; [[ $p == */* ]] && proto=${p#*/}
      block+=$'\n'"-A MAKIT-EGRESS -p $proto --dport $port -j RETURN"
    done
    block+=$'\n'"-A MAKIT-EGRESS -m limit --limit 6/min -j LOG --log-prefix \"[makit egress] \""
    block+=$'\n'"-A MAKIT-EGRESS -j REJECT"
  fi
  # ufw-docker: traffic between private networks passes; new connections from outside to containers go through ufw's
  # route rules (ufw route allow …) and are dropped otherwise.
  for n in "${PRIVATE_NETS[@]}"; do block+=$'\n'"-A DOCKER-USER -j RETURN -s $n"; done
  block+=$'\n'"-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN"
  block+=$'\n'"-A DOCKER-USER -j ufw-user-forward"
  for n in "${PRIVATE_NETS[@]}"; do block+=$'\n'"-A DOCKER-USER -j DROP -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d $n"; done
  for n in "${PRIVATE_NETS[@]}"; do block+=$'\n'"-A DOCKER-USER -j DROP -p udp -m udp --dport 0:32767 -d $n"; done
  block+=$'\n'"-A DOCKER-USER -j RETURN"$'\n'"COMMIT"$'\n'"# END makit docker"

  if [[ $MAKIT_DRY -eq 1 ]]; then printf '%s\n' "$block" | sed 's/^/  [dry-run] /'; else
    cp "$UFW_AFTER" "$UFW_AFTER.makit-bak"
    sed -i '/^# BEGIN makit docker/,/^# END makit docker/d' "$UFW_AFTER"
    printf '%s\n' "$block" >> "$UFW_AFTER"
  fi
  local sp; sp=" $(ssh_ports | tr '\n' ' ') 22 "
  for p in "${ports[@]}"; do
    [[ $sp == *" ${p%%/*} "* ]] && continue
    local proto=tcp; [[ $p == */* ]] && proto=${p#*/}
    run ufw route allow proto "$proto" from any to any port "${p%%/*}" >/dev/null
    info "containers: allow $p from the internet"
  done
  if [[ $MAKIT_DRY -eq 0 ]] && ! ufw reload >/dev/null; then
    mv "$UFW_AFTER.makit-bak" "$UFW_AFTER"; ufw reload >/dev/null || true
    die "ufw rejected the rules — restored the previous $UFW_AFTER"
  fi
  ok "published container ports now follow ufw (only the ports above are reachable from the internet)"
  if [[ ${#eg[@]} -gt 0 ]]; then ok "containers may connect out only to: ${eg[*]} + DNS (rejections: journalctl -k | grep 'makit egress')"
  else info "containers may connect anywhere (restrict with --egress \"443/tcp\"; makit docs egress)"; fi
}
