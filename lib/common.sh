# shellcheck shell=bash
# Shared helpers for makit commands. Sourced by bin/makit; never executed directly.

MAKIT_DRY=${MAKIT_DRY:-0}
MAKIT_YES=${MAKIT_YES:-0}

if [[ -t 1 ]]; then C_B=$'\e[1m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_G=$'\e[32m'; C_0=$'\e[0m'; else C_B=; C_Y=; C_R=; C_G=; C_0=; fi

step() { printf '\n%s▶ %s%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '  %s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s⚠ %s%s\n' "$C_Y" "$*" "$C_0" >&2; }
die()  { printf '%s✗ %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 1; }

# Runs a command, or prints it in dry-run mode.
run() {
  if [[ $MAKIT_DRY -eq 1 ]]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}

# Writes stdin to a file (mode optional), or prints what would be written.
write_file() {
  local path=$1 mode=${2:-0644} content
  content=$(cat)
  if [[ $MAKIT_DRY -eq 1 ]]; then
    printf '  [dry-run] write %s (%s):\n' "$path" "$mode"; printf '%s\n' "$content" | sed 's/^/      /'
    return
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$content" > "$path"
  chmod "$mode" "$path"
}

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo -i, or ssh root@host)."; }

# Debian/Ubuntu only: every command relies on apt, systemd and ufw.
require_supported_os() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release: unsupported system."
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    ubuntu:*|debian:*|*:*debian*) ;;
    *) die "Unsupported OS '${PRETTY_NAME:-unknown}': makit supports Ubuntu and Debian." ;;
  esac
  # shellcheck disable=SC2034 # used by the command files
  OS_ID=${ID}
  # shellcheck disable=SC2034
  OS_CODENAME=${VERSION_CODENAME:-}
  # shellcheck disable=SC2034
  OS_NAME=${PRETTY_NAME:-$ID}
  # shellcheck disable=SC2034
  ARCH=$(dpkg --print-architecture)
}

have() { command -v "$1" >/dev/null 2>&1; }

apt_install() {
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@"
}

# Asks for confirmation unless --yes was given; dry-run never asks.
confirm() {
  [[ $MAKIT_YES -eq 1 || $MAKIT_DRY -eq 1 ]] && return 0
  [[ -t 0 ]] || die "$1 — re-run with --yes to confirm non-interactively."
  local reply; read -r -p "  $1 [y/N] " reply
  [[ $reply == y || $reply == Y ]]
}

mem_mb() { awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo; }

# "4G", "512M", "2048" (MiB) → MiB.
size_to_mb() {
  local s=${1^^}
  case "$s" in
    *G) echo $(( ${s%G} * 1024 )) ;;
    *M) echo "${s%M}" ;;
    ''|*[!0-9]*) return 1 ;;
    *) echo "$s" ;;
  esac
}
