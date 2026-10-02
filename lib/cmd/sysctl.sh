# shellcheck shell=bash
SYSCTL_FILE=/etc/sysctl.d/90-makit.conf

# Sets KEY=VALUE pairs in $SYSCTL_FILE (replacing an earlier value of the same key) and applies them.
sysctl_set() {
  local kv key val
  for kv in "$@"; do
    [[ $kv == *=* ]] || die "Expected KEY=VALUE, got: $kv"
    key=${kv%%=*}; val=${kv#*=}
    [[ $key =~ ^[a-z0-9_.-]+$ ]] || die "Bad sysctl key: $key"
    if [[ $MAKIT_DRY -eq 1 ]]; then info "[dry-run] $key = $val ($SYSCTL_FILE)"; continue; fi
    mkdir -p "$(dirname "$SYSCTL_FILE")"; touch "$SYSCTL_FILE"
    grep -v "^${key//./\\.}[[:space:]]*=" "$SYSCTL_FILE" > "$SYSCTL_FILE.tmp" || true
    printf '%s = %s\n' "$key" "$val" >> "$SYSCTL_FILE.tmp"
    mv "$SYSCTL_FILE.tmp" "$SYSCTL_FILE"
    if sysctl -q -w "$key=$val" >/dev/null 2>&1; then ok "$key = $val"; else warn "$key saved but not applied now (read-only here?) — applies on boot"; fi
  done
}

cmd_sysctl() {
  [[ ${1:-} == --help || $# -eq 0 ]] && { echo "makit sysctl KEY=VALUE… — persist in $SYSCTL_FILE. Presets: opensearch (vm.max_map_count=262144)."; return; }
  require_root
  step "Kernel settings"
  local a out=()
  for a in "$@"; do
    case "$a" in
      opensearch|elasticsearch) out+=(vm.max_map_count=262144) ;;
      *) out+=("$a") ;;
    esac
  done
  sysctl_set "${out[@]}"
}
