# shellcheck shell=bash
# Components makit manages, with a read-only check for each. Used by `makit list` and the Setup tab of `makit top`.
# Each line: id|title|install command|description
COMPONENTS=(
  "upgrade|System updates|system-upgrade|Installed packages are up to date"
  "base|Base packages|base|curl, git, rsync, ufw, fail2ban, unattended-upgrades, jq…"
  "swap|Swap|swap|A swap file sized for this machine's RAM"
  "docker|Docker|docker|Docker Engine + Compose, container logs capped"
  "firewall|Firewall|firewall|ufw: only SSH, HTTP and HTTPS open"
  "updates|Security updates|updates|Unattended security upgrades"
  "ssh|SSH key-only|ssh|Password login disabled (needs a key for root)"
  "opensearch|OpenSearch kernel setting|sysctl opensearch|vm.max_map_count = 262144 (OpenSearch/Elasticsearch)"
)

# Prints "ok|<detail>" or "missing|<detail>" for a component id.
check_component() {
  local id=$1 n
  case "$id" in
    upgrade)
      n=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ' || true)
      if [[ $n -eq 0 ]]; then echo "ok|up to date"; else echo "missing|$n package(s) can be upgraded"; fi ;;
    base)
      local p miss=()
      for p in "${BASE_PACKAGES[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || miss+=("$p"); done
      if [[ ${#miss[@]} -eq 0 ]]; then echo "ok|${#BASE_PACKAGES[@]} packages"; else echo "missing|not installed: ${miss[*]}"; fi ;;
    swap)
      n=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
      if [[ $n -gt 0 ]]; then echo "ok|${n} MiB"; elif [[ $(swap_auto_mb) -eq 0 ]]; then echo "ok|not needed ($(mem_mb) MiB RAM)"; else echo "missing|no swap"; fi ;;
    docker)
      if ! have docker; then echo "missing|not installed"
      elif ! systemctl is-active --quiet docker 2>/dev/null; then echo "missing|installed but not running"
      else echo "ok|$(docker --version 2>/dev/null | sed 's/Docker version //; s/,.*//')"; fi ;;
    firewall)
      if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then echo "ok|active, $(ufw status 2>/dev/null | grep -c ALLOW) rule(s)"
      else echo "missing|inactive"; fi ;;
    updates)
      if grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then echo "ok|enabled"; else echo "missing|disabled"; fi ;;
    ssh)
      if ! have sshd; then echo "ok|no SSH server"
      elif sshd -T 2>/dev/null | grep -qx 'passwordauthentication no'; then echo "ok|key-only"
      else echo "missing|password login allowed"; fi ;;
    opensearch)
      n=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
      if [[ $n -ge 262144 ]]; then echo "ok|$n"; else echo "missing|$n (needs 262144)"; fi ;;
    *) echo "missing|unknown component" ;;
  esac
}

json_str() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '"%s"' "$s"; }

cmd_list() {
  [[ ${1:-} == --help ]] && { echo "makit list [--json] — what makit manages and whether each part is in place (read-only)."; return; }
  local json=0; [[ ${1:-} == --json ]] && json=1
  local line id title cmd desc res state detail first=1
  [[ $json -eq 1 ]] && printf '['
  for line in "${COMPONENTS[@]}"; do
    IFS='|' read -r id title cmd desc <<<"$line"
    res=$(check_component "$id"); state=${res%%|*}; detail=${res#*|}
    if [[ $json -eq 1 ]]; then
      [[ $first -eq 1 ]] || printf ','; first=0
      printf '{"id":%s,"title":%s,"command":%s,"description":%s,"installed":%s,"detail":%s}' \
        "$(json_str "$id")" "$(json_str "$title")" "$(json_str "$cmd")" "$(json_str "$desc")" \
        "$([[ $state == ok ]] && echo true || echo false)" "$(json_str "$detail")"
    else
      if [[ $state == ok ]]; then printf '  %s✓%s %-26s %s\n' "$C_G" "$C_0" "$title" "$detail"
      else printf '  %s✗%s %-26s %s  →  makit %s\n' "$C_Y" "$C_0" "$title" "$detail" "$cmd"; fi
    fi
  done
  [[ $json -eq 1 ]] && printf ']\n'
  return 0
}
