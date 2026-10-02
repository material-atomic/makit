#!/usr/bin/env bash
# Cuts a release from a clean main: scripts/release.sh 0.2.0
# Bumps VERSION + pinned install URLs, commits, tags, pushes, builds makit-core and publishes the GitHub release.
set -euo pipefail
cd "$(dirname "$0")/.."
v=${1:?usage: scripts/release.sh X.Y.Z}; tag="v$v"
[[ -z $(git status --porcelain) ]] || { echo "working tree not clean" >&2; exit 1; }
tests/smoke.sh >/dev/null
echo "$v" > VERSION
perl -pi -e "s/MAKIT_VERSION:-v[0-9.]+/MAKIT_VERSION:-$tag/; s#makit/v[0-9.]+/install.sh#makit/$tag/install.sh#" install.sh
perl -pi -e "s#makit/v[0-9.]+/install.sh#makit/$tag/install.sh#g" README.md
git commit -qam "release: $tag"
git tag -a "$tag" -m "makit $tag"
git push -q origin main "$tag"
scripts/build.sh "$v"
sleep 3
tarsum=$(curl -fsSL "https://codeload.github.com/material-atomic/makit/tar.gz/refs/tags/$tag" | shasum -a 256 | cut -d' ' -f1)
notes=$(awk -v t="## $tag" '$0==t{f=1;next} /^## /{f=0} f' CHANGELOG.md)
gh release create "$tag" dist/makit-core-linux-amd64 dist/makit-core-linux-arm64 dist/SHA256SUMS --title "makit $tag" --notes "$notes

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/material-atomic/makit/$tag/install.sh | bash
\`\`\`

Source tarball SHA256 (\`MAKIT_SHA256\`): \`$tarsum\`
makit-core binaries: see \`SHA256SUMS\` (verified by install.sh)."
echo "released $tag"
