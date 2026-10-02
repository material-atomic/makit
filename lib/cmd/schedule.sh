# shellcheck shell=bash
# docs/security/scheduled-scans.md
SCAN_CONSENT=/etc/makit/scan-consent
SCAN_CONF=/etc/makit/scan.conf
SCAN_LOGS=/var/log/makit/scans

cmd_schedule() {
  local what=${1:-status}; shift || true
  case "$what" in
    --help|help) echo "makit schedule scan daily|weekly|hourly|off|status [--webhook URL] [--all-containers] [--consent]
  Runs 'makit scan' from a systemd timer, keeps the last 30 reports in $SCAN_LOGS and posts a summary to the webhook
  when something MEDIUM or worse is found. Asks for consent once (recorded in $SCAN_CONSENT).
Docs: makit docs scheduled-scans"; return ;;
    status) schedule_status; return ;;
    scan) ;;
    *) die "Usage: makit schedule scan daily|weekly|hourly|off|status" ;;
  esac
  local when=${1:-status} webhook='' args='' consent=0 a; shift || true
  for a in "$@"; do
    case "$a" in
      --webhook=*) webhook=${a#--webhook=} ;;
      --all-containers) args+=" --all-containers --host" ;;
      --consent) consent=1 ;;
      --webhook) die "use --webhook=URL" ;;
      *) die "Unknown option: $a" ;;
    esac
  done
  case "$when" in
    status) schedule_status; return ;;
    off)
      require_root; step "Scheduled scans: off"
      run systemctl disable --now makit-scan.timer >/dev/null 2>&1 || true
      run rm -f /etc/systemd/system/makit-scan.timer /etc/systemd/system/makit-scan.service "$SCAN_CONSENT" "$SCAN_CONF"
      run systemctl daemon-reload; ok "removed (reports kept in $SCAN_LOGS)"; return ;;
    hourly|daily|weekly) ;;
    *) die "Unknown schedule: $when (hourly, daily, weekly, off)" ;;
  esac
  require_root
  step "Scheduled scans: $when"
  info "Each run READS processes, files, start-up entries, configuration and packages (see: makit scan --help)."
  info "It never modifies, deletes, quarantines or uploads anything; only the summary goes to your webhook."
  if [[ $consent -eq 0 && $MAKIT_DRY -eq 0 ]]; then
    [[ -t 0 ]] || die "Consent required: run interactively or pass --consent."
    local reply; read -r -p "  Type 'yes' to allow scheduled scans of this server: " reply
    [[ ${reply,,} == yes ]] || die "Consent not given — nothing scheduled."
  fi
  local who=${SUDO_USER:-$(id -un)}
  printf 'consented_by=%s\nconsented_at=%s\nhost=%s\nschedule=%s\n' "$who" "$(date -Is)" "$(hostname)" "$when" | write_file "$SCAN_CONSENT" 0600
  printf 'WEBHOOK=%q\nSCAN_ARGS=%q\n' "$webhook" "${args# }" | write_file "$SCAN_CONF" 0600
  write_file /etc/systemd/system/makit-scan.service <<UNIT
[Unit]
Description=makit security scan (read-only)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/makit scan-run
Nice=10
IOSchedulingClass=idle
UNIT
  write_file /etc/systemd/system/makit-scan.timer <<UNIT
[Unit]
Description=makit security scan ($when)

[Timer]
OnCalendar=$when
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  run systemctl daemon-reload
  run systemctl enable --now makit-scan.timer >/dev/null
  ok "next run: $(systemctl list-timers makit-scan.timer --no-legend 2>/dev/null | awk '{print $1, $2, $3}')"
  if [[ -n $webhook ]]; then info "alerts → $webhook"; else info "no webhook: results go to journalctl -t makit-scan and $SCAN_LOGS"; fi
}

schedule_status() {
  if systemctl is-enabled --quiet makit-scan.timer 2>/dev/null; then
    ok "scheduled: $(sed -n 's/^schedule=//p' "$SCAN_CONSENT" 2>/dev/null) (consent: $(sed -n 's/^consented_by=//p' "$SCAN_CONSENT" 2>/dev/null))"
    systemctl list-timers makit-scan.timer --no-legend 2>/dev/null | sed 's/^/  /'
  else
    info "no scheduled scan (makit schedule scan daily)"
  fi
  local last; last=$(find "$SCAN_LOGS" -name 'scan-*.json' 2>/dev/null | sort | tail -1)
  [[ -n $last ]] && info "last report: $last"
  return 0
}

# scan-run: what the timer executes. Not meant to be run by hand.
cmd_scan_run() {
  require_root; require_core
  [[ -f $SCAN_CONSENT ]] || die "no consent recorded ($SCAN_CONSENT) — enable with: makit schedule scan daily"
  local WEBHOOK='' SCAN_ARGS=''
  # shellcheck disable=SC1090
  [[ -f $SCAN_CONF ]] && . "$SCAN_CONF"
  cmd_rules update >/dev/null 2>&1 || true
  mkdir -p "$SCAN_LOGS"
  local out code summary worst
  out="$SCAN_LOGS/scan-$(date +%Y%m%d-%H%M%S).json"
  set +e
  # shellcheck disable=SC2086 # SCAN_ARGS holds flags
  MAKIT_SECURITY=$(security_dirs) "$MAKIT_CORE" scan --consent --json $SCAN_ARGS > "$out" 2>/dev/null
  code=$?
  set -e
  find "$SCAN_LOGS" -name 'scan-*.json' | sort | head -n -30 | xargs -r rm -f
  if have jq; then
    summary=$(jq -r '[.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH" or .severity=="MEDIUM")] as $f
      | "makit scan on \(.host): \([$f[] | select(.severity=="CRITICAL")] | length) critical, \([$f[] | select(.severity=="HIGH")] | length) high, \([$f[] | select(.severity=="MEDIUM")] | length) medium\n" +
        ([$f[:8][] | "• [\(.severity)] \(.title) — \(.target) \(.path // "")"] | join("\n"))' "$out")
  else
    summary="makit scan on $(hostname): $(grep -c '"severity": "\(CRITICAL\|HIGH\|MEDIUM\)"' "$out") findings MEDIUM or worse ($out)"
  fi
  worst=ok; [[ $code -eq 1 ]] && worst=alert
  logger -t makit-scan -- "$(head -1 <<<"$summary") — report $out"
  if [[ $worst == alert && -n $WEBHOOK ]]; then
    local body
    if have jq; then body=$(jq -n --arg t "$summary"$'\n'"report: $out" '{text: $t}'); else body="{\"text\": \"makit scan: findings on $(hostname), see $out\"}"; fi
    curl -fsS -m 20 -X POST -H 'Content-Type: application/json' --data "$body" "$WEBHOOK" >/dev/null || logger -t makit-scan "webhook failed"
  fi
  # Channels from 'makit notify add …' (Telegram, Slack, Google Chat, Discord, Teams, ntfy, email) get it too.
  if [[ $worst == alert && -s /etc/makit/notify.yaml ]]; then
    local level=high
    if have jq && [[ $(jq '[.findings[] | select(.severity=="CRITICAL")] | length' "$out") -gt 0 ]]; then level=critical; fi
    printf '%s\nreport: %s\n' "$summary" "$out" | "$MAKIT_CORE" notify send --level "$level" --title "scan findings" --source scan \
      || logger -t makit-scan "notify failed"
  fi
  [[ $code -le 1 ]]
}
