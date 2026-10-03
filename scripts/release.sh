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
perl -pi -e "s#makit/v[0-9.]+/install.sh#makit/$tag/install.sh#g; s#makit\.sh/v[0-9.]+/install.sh#makit.sh/$tag/install.sh#g; s#sh -s -- v[0-9.]+#sh -s -- $tag#g" README.md
perl -pi -e "s/^version: .*/version: $v/; s/^appVersion: .*/appVersion: \"$v\"/" deploy/helm/makit-shield/Chart.yaml
perl -pi -e "s#makit-shield:[0-9]+\.[0-9]+\.[0-9]+#makit-shield:$v#g" docs/security/kubernetes.md
scripts/manifests.sh >/dev/null   # the plain manifests pin the image: the new version
git commit -qam "release: $tag"
git tag -a "$tag" -m "makit $tag"
git push -q origin main "$tag"
scripts/build.sh "$v"
sleep 3
tarsum=$(curl -fsSL "https://codeload.github.com/material-atomic/makit/tar.gz/refs/tags/$tag" | shasum -a 256 | cut -d' ' -f1)
echo "$tarsum  makit-$tag.tar.gz" >> dist/SHA256SUMS   # install.sh verifies the source with it
notes=$(awk -v t="## $tag" '$0==t{f=1;next} /^## /{f=0} f' CHANGELOG.md)
gh release create "$tag" dist/makit-core-linux-amd64 dist/makit-core-linux-arm64 dist/SHA256SUMS --title "makit $tag" --notes "$notes

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/material-atomic/makit/$tag/install.sh | bash
\`\`\`

Source tarball SHA256 (\`MAKIT_SHA256\`): \`$tarsum\`
Source tarball and makit-core binaries: \`SHA256SUMS\` (verified by install.sh)."
echo "released $tag"
echo "next: on the website (RunSnip project makit.sh) add $tag/install.sh (a pinned copy of the previous one) and"
echo "      replace llms-full.txt with the output of scripts/llms-full.sh"
echo "      upload site/playground.html, site/js/playground.js and site/css/playground.css (the WebAssembly is published"
echo "      on the playground branch by .github/workflows/playground.yml)"
