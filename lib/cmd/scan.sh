# shellcheck shell=bash
cmd_scan() {
  require_core
  MAKIT_SECURITY=$(security_dirs) exec "$MAKIT_CORE" scan "$@"
}
