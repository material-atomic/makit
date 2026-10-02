# shellcheck shell=bash
# auto: 2G on small machines, 4G up to 16G of RAM, none above (databases and builds get OOM-killed without it).
swap_auto_mb() {
  local ram; ram=$(mem_mb)
  if (( ram < 2048 )); then echo 2048; elif (( ram <= 16384 )); then echo 4096; else echo 0; fi
}

cmd_swap() {
  local size=${1:-auto}
  [[ $size == --help ]] && { echo "makit swap [SIZE|auto] — /swapfile of SIZE (e.g. 4G, 2048M); auto: 2G if RAM < 2G, 4G up to 16G, none above. Sets vm.swappiness=10."; return; }
  require_root
  step "Swap"
  local want; if [[ $size == auto ]]; then want=$(swap_auto_mb); else want=$(size_to_mb "$size") || die "Bad size: $size (use e.g. 4G or 2048M)"; fi
  info "RAM $(mem_mb) MiB"
  if [[ -f /swapfile ]]; then
    local have_mb=$(( $(stat -c %s /swapfile) / 1048576 ))
    ok "/swapfile already exists (${have_mb} MiB) — left as is"
    (( want > 0 && have_mb != want )) && info "to resize: swapoff /swapfile && rm /swapfile && makit swap ${size}"
  elif (( want == 0 )); then
    ok "plenty of RAM, no swap file needed"
  else
    if ! run fallocate -l "${want}M" /swapfile 2>/dev/null; then
      run dd if=/dev/zero of=/swapfile bs=1M count="$want" status=none   # filesystems without fallocate support
    fi
    run chmod 600 /swapfile
    run mkswap -q /swapfile
    run swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab 2>/dev/null || run sh -c 'echo "/swapfile none swap sw 0 0" >> /etc/fstab'
    ok "swap ${want} MiB enabled"
  fi
  sysctl_set vm.swappiness=10
}
