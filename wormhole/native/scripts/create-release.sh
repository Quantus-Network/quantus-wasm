#!/usr/bin/env bash
# Cut a release of @quantus-network/wormhole: bump the version here and in the
# platform packages, commit, tag `wormhole-vX.Y.Z`, push, and open a GitHub
# Release. Publishing the release triggers the `Native addon` workflow, which
# builds every platform and publishes to npm.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: wormhole/native/scripts/create-release.sh <patch|minor|major|x.y.z>" >&2
  exit 1
fi
cd "$(dirname "$0")/.."
if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is not clean" >&2
  exit 1
fi

version="$(npm version "$1" --no-git-tag-version)"   # prints vX.Y.Z
npx napi version                                       # npm/*/package.json
node -e '
  const fs = require("fs");
  const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
  for (const name of Object.keys(pkg.optionalDependencies)) pkg.optionalDependencies[name] = pkg.version;
  fs.writeFileSync("package.json", JSON.stringify(pkg, null, 2) + "\n");
'                                                      # optionalDependencies
tag="wormhole-$version"
git add package.json npm/*/package.json
git commit -m "@quantus-network/wormhole ${version#v}"
git tag "$tag"
git push --follow-tags
gh release create "$tag" --generate-notes --verify-tag --title "@quantus-network/wormhole ${version#v}"
