# shellcheck shell=bash
SECURITY_CACHE=/var/lib/makit/security

security_dirs() { echo "$MAKIT_HOME/security:$SECURITY_CACHE"; }

cmd_rules() {
  local sub=${1:-list}; shift || true
  case "$sub" in
    --help|help) echo "makit rules list|update|path — the security catalog makit scan uses.
  list          show sources, built-in checks, rules and vulnerabilities in use (--json for tools)
  update [REF]  download the latest catalog from github.com/$MAKIT_REPO (branch or tag, default main) into $SECURITY_CACHE
  path          print the catalog directories, in the order they are read"; return ;;
    path) tr ':' '\n' <<<"$(security_dirs)" ;;
    list) require_core; MAKIT_SECURITY=$(security_dirs) "$MAKIT_CORE" scan --list-rules "$@" ;;
    update)
      require_root; require_core
      local ref=${1:-main} tmp
      step "Security catalog ← github.com/$MAKIT_REPO@$ref"
      tmp=$(mktemp -d)
      # shellcheck disable=SC2064
      trap "rm -rf '$tmp'" RETURN
      curl -fsSL "https://codeload.github.com/$MAKIT_REPO/tar.gz/$ref" -o "$tmp/src.tgz" || die "download failed"
      tar -xzf "$tmp/src.tgz" -C "$tmp" --strip-components=1 --wildcards '*/security/*' || die "no security/ directory in $ref"
      # Load it before switching: a broken or too-new catalog never replaces the working one.
      MAKIT_SECURITY="$tmp/security" "$MAKIT_CORE" scan --list-rules >/dev/null || die "catalog in $ref does not load — kept the current one"
      [[ $MAKIT_DRY -eq 1 ]] && { info "[dry-run] would install it in $SECURITY_CACHE"; return; }
      mkdir -p "$(dirname "$SECURITY_CACHE")"
      rm -rf "$SECURITY_CACHE.new" && cp -r "$tmp/security" "$SECURITY_CACHE.new"
      rm -rf "$SECURITY_CACHE.old"; [[ -d $SECURITY_CACHE ]] && mv "$SECURITY_CACHE" "$SECURITY_CACHE.old"
      mv "$SECURITY_CACHE.new" "$SECURITY_CACHE" && rm -rf "$SECURITY_CACHE.old"
      ok "catalog updated ($ref): $(NO_COLOR=1 FORCE_COLOR='' CLICOLOR_FORCE='' MAKIT_SECURITY=$SECURITY_CACHE "$MAKIT_CORE" scan --list-rules | grep -cE '^  (MK-|CVE-|GHSA-)') entries"
      ;;
    *) die "Unknown: makit rules $sub (list|update|path)" ;;
  esac
}
