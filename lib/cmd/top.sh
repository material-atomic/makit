# shellcheck shell=bash
MAKIT_CORE=${MAKIT_CORE:-"$MAKIT_HOME/libexec/makit-core"}

require_core() { [[ -x $MAKIT_CORE ]] || die "makit-core is missing from this install ($MAKIT_CORE) — reinstall with: makit self-update"; }

cmd_top() {
  [[ ${1:-} == --help ]] && { echo "makit top [--interval 1s] — terminal dashboard (mouse + keyboard): overview, processes, containers, services, disks, logs, setup. Actions need root."; return; }
  require_core
  MAKIT_BIN="$MAKIT_HOME/bin/makit" exec "$MAKIT_CORE" top "$@"
}
