#!/usr/bin/env bash
# Prints llms-full.txt for https://makit.sh: the README and every guide in one Markdown file for language models,
# with relative links made absolute. Regenerate and upload it when the docs change (also at each release):
#   scripts/llms-full.sh > /tmp/llms-full.txt
set -euo pipefail
cd "$(dirname "$0")/.."
raw=https://raw.githubusercontent.com/material-atomic/makit/main
blob=https://github.com/material-atomic/makit/blob/main
guides=(shield bots notifications malware persistence dependencies scheduled-scans incident-response ssh firewall
  docker-ports egress containers updates kernel mounts fail2ban apparmor secrets logging accounts backups)

# absolutize FILE: rewrites ](relative) links against FILE's directory — Markdown to raw files, the rest to GitHub.
absolutize() {
  RAW=$raw BLOB=$blob DIR=$(dirname "$1") perl -pe '
    s{\]\((?!https?:|mailto:|#)([^)\s]+)\)}{
      my ($t) = ($1);
      my ($path, $frag) = $t =~ /^([^#]*)(#.*)?$/;
      my @parts = $ENV{DIR} eq "." ? () : split m{/}, $ENV{DIR};
      for my $p (split m{/}, $path) { next if $p eq "." || $p eq ""; if ($p eq "..") { pop @parts } else { push @parts, $p } }
      my $full = join "/", @parts;
      my $base = ($full =~ /\.md$/ && !$frag) ? $ENV{RAW} : $ENV{BLOB};
      "](" . $base . "/" . $full . ($frag // "") . ")"
    }ge' "$1"
}

cat <<HEAD
# makit — full documentation

> makit is an open-source (MIT) command-line tool for the security of Linux servers you run yourself (Ubuntu and
> Debian): it checks the host and its Docker containers (makit scan), blocks attacks before they reach the app with a
> request shield that also handles bots and AI agents (makit shield), sends alerts (makit notify), sets up and hardens
> new servers (makit init) and shows a terminal dashboard (makit top).

This file joins the README and every guide of the repository (https://github.com/material-atomic/makit), version
$(cat VERSION), generated $(date -u +%Y-%m-%d). Install: \`curl -fsSL https://makit.sh/install.sh | sh\` (as root).
Website: https://makit.sh · Index: https://makit.sh/llms.txt

HEAD
printf '\n---\n\n<!-- source: %s/README.md -->\n\n' "$blob"
absolutize README.md
for g in "${guides[@]}"; do
  printf '\n---\n\n<!-- source: %s/docs/security/%s.md -->\n\n' "$blob" "$g"
  absolutize "docs/security/$g.md"
done
printf '\n---\n\n<!-- source: %s/docs/security/README.md -->\n\n' "$blob"
absolutize docs/security/README.md
