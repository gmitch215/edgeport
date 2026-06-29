#!/usr/bin/env bash
# deploys ./typedoc to the gh-pages branch (latest-only); arg $1 = short git sha
# usage: bash typedoc.sh "$(git rev-parse --short HEAD)"
set -euo pipefail

SHA="${1:-manual}"
OUT_DIR="typedoc"
TMP_DIR="$(mktemp -d)"

if [ ! -d "$OUT_DIR" ]; then
	echo "no $OUT_DIR/ found; run 'bun run docs:build' first" >&2
	exit 1
fi

cp -R "$OUT_DIR"/. "$TMP_DIR"/
touch "$TMP_DIR/.nojekyll"

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

git fetch origin gh-pages || true
if git show-ref --verify --quiet refs/remotes/origin/gh-pages; then
	git checkout gh-pages
	git pull --ff-only origin gh-pages || true
else
	git checkout --orphan gh-pages
fi

# replace tracked content with the fresh build
git rm -rf . >/dev/null 2>&1 || true
cp -R "$TMP_DIR"/. .
rm -rf "$TMP_DIR"

git add -A
if git diff --cached --quiet; then
	echo "no documentation changes"
	exit 0
fi

git commit -m "Update TypeDoc ($SHA)"
git push -f origin gh-pages
