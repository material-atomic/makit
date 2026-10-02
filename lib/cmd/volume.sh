# shellcheck shell=bash
# Block-storage volumes (DigitalOcean, Hetzner…): mount by UUID, optionally host Docker's named volumes on it.

volume_auto_device() {
  local d=() p
  for p in /dev/disk/by-id/scsi-0DO_Volume_* /dev/disk/by-id/scsi-0HC_Volume_* /dev/disk/by-id/google-* /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_*; do
    [[ -e $p && $p != *-part* ]] && d+=("$p")
  done
  [[ ${#d[@]} -eq 1 ]] || die "Found ${#d[@]} attached volumes (${d[*]:-none}) — pass the device explicitly: makit volume /dev/disk/by-id/… /mnt/data"
  echo "${d[0]}"
}

cmd_volume() {
  local dev='' mnt='' docker=0 format=0 a
  for a in "$@"; do
    case "$a" in
      --help) echo "makit volume DEVICE|auto MOUNTPOINT [--docker] [--format]
  Mounts the volume at MOUNTPOINT via /etc/fstab (by UUID, nofail).
  --format  create ext4 if the device has no filesystem (asks first; ERASES the device). Never reformats.
  --docker  keep Docker's named volumes on it: MOUNTPOINT/docker-volumes is bind-mounted on
            /var/lib/docker/volumes, Docker waits for the mount, existing volumes are copied over."; return ;;
      --docker) docker=1 ;;
      --format) format=1 ;;
      -*) die "Unknown option: $a" ;;
      *) if [[ -z $dev ]]; then dev=$a; elif [[ -z $mnt ]]; then mnt=$a; else die "Unexpected argument: $a"; fi ;;
    esac
  done
  [[ -n $dev && -n $mnt ]] || die "Usage: makit volume DEVICE|auto MOUNTPOINT [--docker] [--format]"
  [[ $mnt == /* ]] || die "MOUNTPOINT must be an absolute path"
  require_root
  step "Volume → $mnt"
  [[ $dev == auto ]] && dev=$(volume_auto_device)
  [[ -b $(readlink -f "$dev") ]] || die "Not a block device: $dev"
  info "device $dev"

  local fstype uuid
  fstype=$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)
  if [[ -z $fstype ]]; then
    [[ $format -eq 1 ]] || die "$dev has no filesystem. Re-run with --format to create ext4 (erases the device)."
    confirm "Format $dev as ext4? Everything on it is erased." || die "Aborted."
    run mkfs.ext4 -q -L makit-data "$dev"
    fstype=ext4
  else
    info "existing $fstype filesystem — not formatting"
  fi
  run mkdir -p "$mnt"
  uuid=$(blkid -o value -s UUID "$dev" 2>/dev/null || echo "<uuid-after-format>")
  if grep -qE "^[^#]*[[:space:]]${mnt}[[:space:]]" /etc/fstab; then
    ok "$mnt already in /etc/fstab"
  else
    run sh -c "echo 'UUID=$uuid $mnt ${fstype:-ext4} defaults,nofail,discard 0 2' >> /etc/fstab"
  fi
  run systemctl daemon-reload
  findmnt -rn "$mnt" >/dev/null 2>&1 || run mount "$mnt"
  ok "mounted $mnt"

  [[ $docker -eq 1 ]] || return 0
  step "Docker named volumes on $mnt"
  local target=/var/lib/docker/volumes src="$mnt/docker-volumes"
  if findmnt -rn "$target" >/dev/null 2>&1; then ok "$target is already a mount"; return 0; fi
  run mkdir -p "$src" "$target"
  write_file /etc/systemd/system/docker.service.d/makit-volumes.conf <<CONF
# Managed by makit: never start Docker without its data volume (would create empty databases on the local disk).
[Unit]
RequiresMountsFor=$target
CONF
  grep -qE "^[^#]*[[:space:]]${target}[[:space:]]" /etc/fstab \
    || run sh -c "echo '$src $target none bind,nofail,x-systemd.requires-mounts-for=$mnt 0 0' >> /etc/fstab"
  run systemctl daemon-reload
  if have docker; then
    run systemctl stop docker.socket docker
    run rsync -aHAX "$target/" "$src/"   # keep whatever volumes already exist
  fi
  run mount "$target"
  have docker && run systemctl start docker
  ok "$target → $src"
}
