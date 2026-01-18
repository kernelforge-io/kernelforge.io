#!/bin/bash
set -euo pipefail

MAIN_BRANCH="master"
TEMP_BRANCH="temp-initial-rewrite"

echo "[*] Sanity: show current branch"
git rev-parse --abbrev-ref HEAD

echo "[*] Ensure a .gitignore exists for Hugo output/caches..."
cat > .gitignore <<'EOF'
public/
resources/
.hugo_build.lock
.hugo_cache/
EOF

echo "[*] Removing any generated output from working tree (if present)..."
rm -rf public/ resources/ .hugo_build.lock .hugo_cache/ || true

echo "[*] Creating orphan branch: ${TEMP_BRANCH}"
git checkout --orphan "${TEMP_BRANCH}"

echo "[*] Resetting index to avoid carrying over staged state..."
git reset

echo "[*] Staging tracked content..."
git add -A

echo "[*] Committing clean history..."
git commit -m "Initial public release"

echo "[*] Replacing branch ${MAIN_BRANCH}..."
# Delete local main if it exists
if git show-ref --verify --quiet "refs/heads/${MAIN_BRANCH}"; then
  git branch -D "${MAIN_BRANCH}"
fi

git branch -m "${MAIN_BRANCH}"

echo "[*] Force pushing rewritten history to origin/${MAIN_BRANCH}..."
git push --force origin "${MAIN_BRANCH}"

echo "[*] Done. Now set default branch to '${MAIN_BRANCH}' in GitHub repo settings if needed."

