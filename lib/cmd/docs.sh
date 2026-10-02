# shellcheck shell=bash
DOCS_DIR=docs/security

cmd_docs() {
  local topic=${1:-} f
  [[ $topic == --help ]] && { echo "makit docs [TOPIC|RULE-ID] — security guides shipped with makit (makit docs ssh, makit docs MK-DOCKER-SOCK)."; return; }
  if [[ -z $topic ]]; then
    printf '%sSecurity guides%s (makit docs <topic>):\n' "$C_B" "$C_0"
    for f in "$MAKIT_HOME/$DOCS_DIR"/*.md; do
      [[ $(basename "$f") == README.md ]] && continue
      printf '  %-20s %s\n' "$(basename "$f" .md)" "$(sed -n 's/^# //p' "$f" | head -1)"
    done
    printf '\nOnline: https://github.com/material-atomic/makit/tree/v%s/%s\n' "$MAKIT_VERSION" "$DOCS_DIR"
    return
  fi
  if [[ $topic == MK-* ]]; then # rule id → its page
    local doc
    doc=$(grep -h -E "^[[:space:]]*$topic:" "$MAKIT_HOME/security/rules/builtin.yaml" 2>/dev/null | sed -n 's/.*doc: *\([^,#}]*\).*/\1/p' | head -1)
    [[ -n $doc ]] || doc=$(grep -l -E "^id: *$topic\$" "$MAKIT_HOME"/security/rules/*.yaml 2>/dev/null | head -1 | xargs -r sed -n 's/^doc: *\([^#]*\).*/\1/p')
    [[ -n $doc ]] || die "No documentation for rule $topic"
    topic=$(basename "${doc%%#*}" .md)
  fi
  f="$MAKIT_HOME/$DOCS_DIR/${topic%.md}.md"
  [[ -f $f ]] || die "No guide named '$topic' — run 'makit docs' for the list"
  if [[ -t 1 ]] && have less; then less -R "$f"; else cat "$f"; fi
}
