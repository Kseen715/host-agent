#!/usr/bin/env bash
# Commits the badges in <dir> to the orphan branch `badges`, where the
# README's shields.io links read them; nothing when they are the same.
set -euo pipefail

dir=$1
git config user.name "github-actions[bot]"
git config user.email \
  "41898282+github-actions[bot]@users.noreply.github.com"
if git fetch --depth=1 origin badges; then
  git checkout -B badges FETCH_HEAD
else
  git checkout --orphan badges
  git rm -r -q --cached .
  git clean -f -d -q
fi
cp "$dir"/*.json .
git add ./*.json
if git diff --cached --quiet; then
  echo "Badges unchanged"
  exit 0
fi
git commit -q -m "chore: update badges for ${GITHUB_SHA:-local}"
git push origin badges
