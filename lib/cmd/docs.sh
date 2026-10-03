# shellcheck shell=bash
DOCS_DIR=docs/security

cmd_docs() {
  local topic=${1:-} f
  [[ $topic == --help ]] && { echo "makit docs [TOPIC|RULE-ID] — security guides shipped with makit (makit docs ssh, makit docs MK-DOCKER-SOCK)."; return; }
  if [[ -z $topic ]]; then
    printf '%sSecurity guides%s (makit docs <topic>):\n' "$C_B" "$C_0"
    for f in "$MAKIT_HOME/$DOCS_DIR"/*.md; do
      [[ $(basename "$f") == README.md ]] && continue
      printf '  %s%-20s%s %s\n' "$C_C" "$(basename "$f" .md)" "$C_0" "$(sed -n 's/^# //p' "$f" | head -1)"
    done
    printf '\n%sOnline:%s https://github.com/material-atomic/makit/tree/v%s/%s\n' "$C_D" "$C_0" "$MAKIT_VERSION" "$DOCS_DIR"
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
  if [[ -t 1 ]] && have less; then md_colour < "$f" | less -R; else md_colour < "$f"; fi
}

# Colours a Markdown guide for the terminal: headings, code blocks, `code`, **bold** and links. Plain without colour.
md_colour() {
  if [[ -z $C_0 ]]; then cat; return; fi
  B=$C_B D=$C_D C=$C_C Y=$C_Y Z=$C_0 perl -pe '
    BEGIN { ($B, $D, $C, $Y, $Z) = @ENV{qw(B D C Y Z)}; $code = 0 }
    if (/^```/) { $code = !$code; $_ = "$D$_"; s/\n$/$Z\n/; next }
    if ($code) { s/^(.*)$/$C$1$Z/; next }
    if (s/^(#{1,2} )(.*)$/$B$C$1$2$Z/) { next }
    if (s/^(#{3,} )(.*)$/$B$1$2$Z/) { next }
    s/^(\s*)([-*]|\d+\.) /$1$Y$2$Z /;
    s/`([^`]+)`/$C$1$Z/g;
    s/\*\*([^*]+)\*\*/$B$1$Z/g;
    s/\[([^\]]+)\]\(([^)]+)\)/$1 $D($2)$Z/g;'
}
