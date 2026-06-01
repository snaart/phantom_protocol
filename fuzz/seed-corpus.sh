#!/usr/bin/env bash
#
# Populate the (gitignored, fuzzer-grown) corpus directory for a target from the
# committed seeds under fuzz/seeds/<target>/.
#
# libFuzzer reads and grows fuzz/corpus/<target>/ in place; that directory is
# .gitignored because the fuzzer writes coverage-increasing inputs into it at
# runtime. The *seeds* — valid, canonical inputs that unlock the parsers'
# success paths immediately — are committed under fuzz/seeds/<target>/ and
# copied in here before a run (locally and in CI).
#
# Usage:
#   fuzz/seed-corpus.sh <target>   # one target
#   fuzz/seed-corpus.sh            # every target with a seeds/ dir
set -euo pipefail

cd "$(dirname "$0")/.."

seed_one() {
  local target="$1"
  local src="fuzz/seeds/$target"
  local dst="fuzz/corpus/$target"
  mkdir -p "$dst"
  if [ -d "$src" ]; then
    # Copy each seed; ignore an empty dir.
    find "$src" -type f -exec cp -f {} "$dst"/ \;
  fi
  echo "seeded $dst ($(find "$dst" -type f | wc -l | tr -d ' ') files)"
}

if [ "$#" -ge 1 ]; then
  seed_one "$1"
else
  for d in fuzz/seeds/*/; do
    [ -d "$d" ] || continue
    seed_one "$(basename "$d")"
  done
fi
