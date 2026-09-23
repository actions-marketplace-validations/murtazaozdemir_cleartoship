#!/usr/bin/env bash
# Every version literal in the docs must equal package.json's version.
#
# action.yml resolves its own version without a literal, because that line was
# twice left naming the previous release during a bump. Prose cannot do that,
# so it is asserted instead — by ci.yml on every push and by release.yml before
# a tag ships. The landing page is included because it once kept saying v0.8.0,
# live, five minor releases after 0.8.0.
#
# What counts as a version literal naming this package:
#   - `cleartoship@vX.Y.Z`                    (`uses: murtazaozdemir/cleartoship@v…`)
#   - `cleartoship/releases/download/vX.Y.Z`  (a versioned release-download URL)
#   - `class="pill">vX.Y.Z<`                  (the version pill in the site footer)
set -euo pipefail
cd "$(dirname "$0")/.."

ver=$(node -p "require('./package.json').version")
files=(README.md examples/*.yml site/public/*.html)
pattern='(cleartoship@|cleartoship/releases/download/|class="pill">)v[0-9]+\.[0-9]+\.[0-9]+'

bad=$(grep -ohE "$pattern" "${files[@]}" \
      | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | sort -u | grep -vx "v${ver}" || true)
if [ -n "$bad" ]; then
  echo "::error::docs name $(echo $bad) but package.json declares v${ver}"
  grep -nE "$pattern" "${files[@]}" | grep -v "v${ver}" || true
  exit 1
fi
n=$(grep -ohE "$pattern" "${files[@]}" | wc -l | tr -d ' ')
echo "all ${n} version literals in the docs say v${ver}"
