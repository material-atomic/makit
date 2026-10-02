# shellcheck shell=bash
MAKIT_REPO=${MAKIT_REPO:-material-atomic/makit}

latest_release() {
  curl -fsSL "https://api.github.com/repos/$MAKIT_REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1
}

# version_gt A B: true when A > B (vX.Y.Z or X.Y.Z).
version_gt() { [[ ${1#v} != "${2#v}" && $(printf '%s\n%s\n' "${1#v}" "${2#v}" | sort -V | tail -1) == "${1#v}" ]]; }

cmd_upgrade() {
  local check=0 want='' a
  for a in "$@"; do
    case "$a" in
      --help) echo "makit upgrade [--check] [vX.Y.Z] — check GitHub for a newer makit and install it (asks first; --yes to skip).
  --check   only report whether a newer version exists (exit 0 up to date, 10 update available)
  vX.Y.Z    install exactly that version (also to downgrade)
System packages: makit system-upgrade."; return ;;
      --check) check=1 ;;
      v[0-9]*|[0-9]*) want=$a ;;
      *) die "Unknown option: $a" ;;
    esac
  done
  local current="v$MAKIT_VERSION" latest
  latest=$(latest_release) || true
  [[ -n $latest ]] || die "Could not reach GitHub to find the latest makit release."
  if [[ $check -eq 1 ]]; then
    if version_gt "$latest" "$current"; then
      info "makit $current → $latest available: https://github.com/$MAKIT_REPO/releases/tag/$latest"
      info "upgrade with: makit upgrade"
      return 10
    fi
    ok "makit $current is the latest version"
    return 0
  fi
  [[ -n $want ]] || want=$latest
  [[ $want == v* ]] || want="v$want"
  if [[ $want == "$current" ]]; then ok "already on $current"; return 0; fi
  if [[ -z ${1:-} || $want == "$latest" ]] && ! version_gt "$want" "$current"; then ok "makit $current is the latest version"; return 0; fi
  require_root
  step "makit $current → $want"
  info "release notes: https://github.com/$MAKIT_REPO/releases/tag/$want"
  confirm "Install makit $want?" || die "Aborted."
  run sh -c "curl -fsSL https://raw.githubusercontent.com/$MAKIT_REPO/$want/install.sh | MAKIT_VERSION=$want bash"
}

# Kept for v0.1/v0.2 muscle memory.
cmd_self_update() { cmd_upgrade "$@"; }
