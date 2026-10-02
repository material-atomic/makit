# shellcheck shell=bash
# docs/security/shield.md
SHIELD_CONF=/etc/makit/shield.yaml
SHIELD_UNIT=/etc/systemd/system/makit-shield.service

shield_default_config() {
  cat <<'YAML'
# makit shield — IP gate for web traffic. Guide: makit docs shield
mode: observe                # block | observe (only log what would be blocked) — makit shield mode block|observe
ask: true                    # Caddy/nginx ask makit (/check); off = /check allows everything — makit shield ask on|off
edge: false                  # makit in front of Caddy/nginx (listeners below) — makit shield edge on|off
admin: 127.0.0.1:9180        # /check endpoint for Caddy forward_auth / nginx auth_request (makit shield snippet caddy|nginx)
                             # Caddy/nginx in Docker: listen on the bridge address too, e.g. 172.17.0.1:9180
trusted_proxies: [cloudflare]   # only these peers may tell the client IP (CF-Connecting-IP); add your load balancer CIDRs
client_ip_header: CF-Connecting-IP
allow: []                    # never blocked, e.g. [203.0.113.0/24, 198.51.100.7]
rules: true                  # HTTP rules from the catalog (security/http/*.yaml), with automatic bans
kernel_block: false          # also drop blocked IPs in the kernel (nftables) — for ports makit does not see, or floods
snapshot:
  path: /var/log/makit/shield/requests.jsonl
  max_mb: 50
  keep: 5
listeners: []                # used when edge is on: makit in front of Caddy/nginx. Example:
#  - name: https
#    listen: ":443"
#    tls: { acme: [example.com, www.example.com], email: you@example.com }   # or { cert: origin.pem, key: origin.key }
#    upstream: http://127.0.0.1:8080
#  - name: http
#    listen: ":80"
#    upstream: http://127.0.0.1:8080
YAML
}

shield_ensure_config() { [[ -f $SHIELD_CONF ]] || { shield_default_config | write_file "$SHIELD_CONF" 0640; }; }

# shield_set KEY VALUE — edits the config through makit-core (keeps comments); the gate reloads within 2 s.
shield_set() {
  shield_ensure_config
  run "$MAKIT_CORE" shield set "$1" "$2" >/dev/null
}

shield_start() {
  shield_install_unit
  if systemctl is-active --quiet makit-shield 2>/dev/null; then run systemctl reload makit-shield
  else run systemctl enable --now makit-shield >/dev/null 2>&1; fi
}

shield_install_unit() {
  write_file "$SHIELD_UNIT" <<UNIT
[Unit]
Description=makit shield (IP gate)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$MAKIT_CORE shield serve
ExecReload=/bin/kill -HUP \$MAINPID
Environment=MAKIT_SECURITY=$(security_dirs)
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  run systemctl daemon-reload
}

cmd_shield() {
  local sub=${1:-status}; shift || true
  case "$sub" in
    --help|help)
      echo "makit shield on [--observe] | off | status | edit | uninstall
makit shield ask on|off      Caddy/nginx ask makit before each request (/check); off = always allow
makit shield edge on|off     makit in front of Caddy/nginx (the listeners in $SHIELD_CONF)
makit shield mode block|observe
makit shield ban|unban|allow|unallow|list|check|log|snippet …   (makit shield help-core for details)
Blocks IPs from its own set (no ipset), Cloudflare-aware: behind Cloudflare it reads the visitor's IP from
CF-Connecting-IP, but only when the connection really comes from Cloudflare. Two ways to use it:
  · Caddy/nginx ask makit before each request (makit shield snippet caddy|nginx)
  · makit in front of Caddy/nginx (listeners in $SHIELD_CONF)
Docs: makit docs shield"; return ;;
    help-core) require_core; "$MAKIT_CORE" shield help; return ;;
    on)
      require_root; require_core
      local mode=block; [[ ${1:-} == --observe ]] && mode=observe
      step "makit shield: $mode"
      shield_set mode "$mode"
      shield_set ask on
      shield_start
      ok "gate on ($mode, ask on). Config: $SHIELD_CONF"
      info "Caddy/nginx: makit shield snippet caddy|nginx · lists: makit shield ban|allow|list · requests: makit shield log"
      ;;
    off)
      require_root; require_core
      step "makit shield: off"
      shield_set ask off
      shield_set edge off
      ok "ask and edge off: everything is allowed; the gate keeps answering so Caddy/nginx keep working (remove it: makit shield uninstall)"
      ;;
    ask|edge)
      require_root; require_core
      local v=${1:-}; [[ $v == on || $v == off ]] || die "Usage: makit shield $sub on|off"
      shield_set "$sub" "$v"
      [[ $v == on ]] && shield_start
      if [[ $sub == edge && $v == on ]]; then
        grep -qE '^[[:space:]]*-[[:space:]]*name:|^[[:space:]]*-[[:space:]]*listen:' "$SHIELD_CONF" || warn "no listeners configured yet: makit shield edit (makit docs shield)"
      fi
      ok "$sub $v"
      ;;
    mode)
      require_root; require_core
      local v=${1:-}; [[ $v == block || $v == observe ]] || die "Usage: makit shield mode block|observe"
      shield_set mode "$v"; ok "mode $v"
      ;;
    edit)
      require_root
      [[ -f $SHIELD_CONF ]] || { shield_default_config | write_file "$SHIELD_CONF" 0640; }
      "${EDITOR:-vi}" "$SHIELD_CONF"
      run systemctl reload makit-shield 2>/dev/null || true
      ;;
    uninstall)
      require_root
      step "makit shield: uninstall"
      warn "remove the makit snippet from Caddy/nginx first, or they will answer 502"
      run systemctl disable --now makit-shield >/dev/null 2>&1 || true
      run rm -f "$SHIELD_UNIT"
      run systemctl daemon-reload
      have nft && run nft delete table inet makit_shield 2>/dev/null || true
      ok "removed (lists kept in /var/lib/makit/shield, config in $SHIELD_CONF)"
      ;;
    status)
      if systemctl is-active --quiet makit-shield 2>/dev/null; then
        ok "running — mode $(sed -n 's/^mode: *\([a-z]*\).*/\1/p' "$SHIELD_CONF" 2>/dev/null), ask $(sed -n 's/^ask: *\([a-z]*\).*/\1/p' "$SHIELD_CONF" 2>/dev/null), edge $(sed -n 's/^edge: *\([a-z]*\).*/\1/p' "$SHIELD_CONF" 2>/dev/null)"
        require_core; "$MAKIT_CORE" shield status; echo
      else
        info "not running (makit shield on)"
      fi
      ;;
    *) require_core; MAKIT_SECURITY=$(security_dirs) exec "$MAKIT_CORE" shield "$sub" "$@" ;;
  esac
}
