#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: scripts/create-release.sh <patch|minor|major|x.y.z>" >&2
  exit 1
fi

npm version "$1"
