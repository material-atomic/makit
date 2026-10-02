# shellcheck shell=bash
# docs/security/notifications.md
cmd_notify() {
  require_core
  case ${1:-} in
    ''|help|--help|-h|list) ;;
    *) require_root ;; # notify.yaml holds tokens (mode 600)
  esac
  exec "$MAKIT_CORE" notify "$@"
}
