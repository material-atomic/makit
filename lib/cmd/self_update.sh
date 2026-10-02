# shellcheck shell=bash
MAKIT_REPO=${MAKIT_REPO:-material-atomic/makit}

cmd_self_update() {
  [[ ${1:-} == --help ]] && { echo "makit self-update [vX.Y.Z] — install that release (default: latest) from github.com/$MAKIT_REPO."; return; }
  require_root
  local want=${1:-}
  if [[ -z $want ]]; then
    want=$(curl -fsSL "https://api.github.com/repos/$MAKIT_REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    [[ -n $want ]] || die "Could not find the latest release of $MAKIT_REPO"
  fi
  [[ $want == v* ]] || want="v$want"
  if [[ "v$MAKIT_VERSION" == "$want" ]]; then ok "already on $want"; return; fi
  step "makit $MAKIT_VERSION → $want"
  run sh -c "curl -fsSL https://raw.githubusercontent.com/$MAKIT_REPO/$want/install.sh | MAKIT_VERSION=$want bash"
}
