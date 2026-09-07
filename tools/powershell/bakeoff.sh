#!/usr/bin/env bash
# Reproduce the PowerShell grammar bake-off recorded in docs/powershell-parser.md.
#
# Compiles each candidate grammar from its pinned commit and counts ERROR nodes
# over tools/powershell/bakeoff-corpus/. Lower is better. MISSING is not a
# matchable kind in ast-grep, so ERROR node counts are the measure.
#
# This exists so the selection is auditable rather than asserted: anyone can
# re-run it and get the table in the docs.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
sg="$root/node_modules/.bin/ast-grep"
corpus="$here/bakeoff-corpus"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/rules"
cat > "$work/rules/error.yml" <<'YAML'
id: psh-parse-error
language: powershell
severity: error
message: parse error
rule:
  kind: ERROR
YAML

# name repository commit
candidates=(
  "wharflab https://github.com/wharflab/tree-sitter-powershell b783f6375530f632cbbb5bc411d333593f541ae7"
  "airbus   https://github.com/airbus-cert/tree-sitter-powershell d398441825243b00e317e87e1829b9d6a3e54ce0"
)

for entry in "${candidates[@]}"; do
  read -r name repo commit <<<"$entry"
  echo "==> building $name @ $commit"
  d="$work/$name"
  mkdir -p "$d"
  curl -fsSL "$repo/archive/$commit.tar.gz" | tar xz -C "$d" --strip-components=1
  cc -shared -fPIC -O2 -I "$d/src" -o "$work/$name.so" \
    "$d/src/parser.c" "$d/src/scanner.c"

  cat > "$work/sg-$name.yml" <<YAML
ruleDirs:
  - rules
customLanguages:
  powershell:
    libraryPath: $work/$name.so
    extensions: [ps1, psm1, psd1]
    expandoChar: 'µ'
YAML
done

echo
printf '%-30s' "corpus file"
for entry in "${candidates[@]}"; do read -r name _ _ <<<"$entry"; printf '%10s' "$name"; done
echo

for f in "$corpus"/*.ps1; do
  printf '%-30s' "$(basename "$f")"
  for entry in "${candidates[@]}"; do
    read -r name _ _ <<<"$entry"
    # ast-grep exits non-zero when it reports error-severity findings, which is
    # the normal case here; capture the output rather than letting set -e abort.
    out="$("$sg" scan -c "$work/sg-$name.yml" --json=compact "$f" 2>/dev/null || true)"
    n="$(printf '%s' "$out" | python3 -c 'import json,sys;print(len(json.load(sys.stdin) or []))')"
    printf '%10s' "$n"
  done
  echo
done

printf '%-30s' "TOTAL"
for entry in "${candidates[@]}"; do
  read -r name _ _ <<<"$entry"
  out="$("$sg" scan -c "$work/sg-$name.yml" --json=compact "$corpus" 2>/dev/null || true)"
  n="$(printf '%s' "$out" | python3 -c 'import json,sys;print(len(json.load(sys.stdin) or []))')"
  printf '%10s' "$n"
done
echo
