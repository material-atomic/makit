# shellcheck shell=bash
cmd_init() {
  local swap=auto ports=() sysctls=() vol_dev='' vol_mnt='' vol_docker=0 vol_format=0 harden=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help) cat <<HELP
makit init [options] — bootstrap a fresh server: base → swap → sysctl → docker → volume → firewall → updates → ssh.
  --swap SIZE|auto|none   swap file size (default auto)
  --port PORT/PROTO       allow a port (repeatable; default 22/tcp 80/tcp 443/tcp 443/udp)
  --sysctl KEY=VALUE      persist a kernel setting (repeatable; 'opensearch' preset)
  --volume DEVICE|auto    mount a block-storage volume …
  --mount PATH            … at PATH (default /mnt/data)
  --docker-volumes        … and keep Docker's named volumes on it
  --format                create ext4 on an empty volume (asks; never reformats)
  --no-ssh-harden         keep SSH password login
Safe to run again: every step checks what is already done.
HELP
        return ;;
      --swap) swap=$2; shift ;;
      --port) ports+=("$2"); shift ;;
      --sysctl) sysctls+=("$2"); shift ;;
      --volume) vol_dev=$2; shift ;;
      --mount) vol_mnt=$2; shift ;;
      --docker-volumes) vol_docker=1 ;;
      --format) vol_format=1 ;;
      --no-ssh-harden) harden=0 ;;
      *) die "Unknown option for init: $1 (see makit init --help)" ;;
    esac
    shift
  done
  require_root; require_supported_os
  [[ $MAKIT_DRY -eq 1 ]] && info "(dry-run: nothing will change)"

  cmd_base
  [[ $swap == none ]] || cmd_swap "$swap"
  [[ ${#sysctls[@]} -eq 0 ]] || cmd_sysctl "${sysctls[@]}"
  cmd_docker
  if [[ -n $vol_dev ]]; then
    local vargs=("$vol_dev" "${vol_mnt:-/mnt/data}")
    [[ $vol_docker -eq 1 ]] && vargs+=(--docker)
    [[ $vol_format -eq 1 ]] && vargs+=(--format)
    cmd_volume "${vargs[@]}"
  fi
  cmd_firewall ${ports[@]+"${ports[@]}"}
  cmd_updates
  if [[ $harden -eq 1 ]]; then cmd_ssh; else step "SSH: key-only login"; info "skipped (--no-ssh-harden)"; fi

  step "Done"
  cmd_status
}
