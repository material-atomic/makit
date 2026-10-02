# shellcheck shell=bash
cmd_scan() {
  require_core
  exec "$MAKIT_CORE" scan "$@"
}
