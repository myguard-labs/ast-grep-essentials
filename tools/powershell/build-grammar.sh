#!/usr/bin/env bash
# Build the pinned PowerShell tree-sitter grammar into a loadable dynamic library.
#
# Deterministic by construction: the source is a specific upstream commit whose
# tarball checksum is verified before a single byte is compiled. A checksum
# mismatch is fatal -- we never build an unverified parser, because ast-grep
# loads it as native code and a substituted grammar silently changes which
# security findings are reported.
#
# Usage: tools/powershell/build-grammar.sh [output-path]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
lock="$here/grammar.lock.json"

# Read one scalar from the lockfile. Errors are reported as a refusal rather
# than a Python traceback: this is the first thing that touches the lockfile,
# so an unreadable one surfaces here, and a build gate's diagnostics are part
# of what makes it usable.
read_lock() {
  python3 -c "
import json, sys
try:
    print(json.load(open(sys.argv[1]))['grammar'][sys.argv[2]])
except (OSError, ValueError, KeyError, TypeError) as exc:
    raise SystemExit('unreadable lockfile: %s' % exc)
" "$lock" "$1"
}

read_lock_or_refuse() {
  if ! value="$(read_lock "$1")"; then
    echo "refusing to build an unverified parser" >&2
    exit 1
  fi
  printf '%s' "$value"
}

repo="$(read_lock_or_refuse repository)"
tag="$(read_lock_or_refuse tag)"
commit="$(read_lock_or_refuse commit)"
symbol="$(read_lock_or_refuse symbol)"
# The include dir is part of the gate, not just a compiler flag: everything
# the archive ships under it is checksummed below, and -I points at the same
# path, so the verified header set and the searched header set are one set.
include_dir="$(read_lock_or_refuse includeDir)"

# Library extension per platform. ast-grep resolves the library through the
# host dynamic loader, so the suffix must be the platform-native one.
case "$(uname -s)" in
  Darwin)            ext=dylib ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) ext=dll ;;
  *)                 ext=so ;;
esac

out="${1:-$root/build/powershell/powershell.$ext}"
mkdir -p "$(dirname "$out")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Validate the lockfile BEFORE fetching anything.
#
# Ordering is part of the gate. If validation ran only after the download, a
# machine with no network would fail at curl and every checksum control would
# pass on a DNS error without ever exercising the checksum logic -- a test
# that passes because a fetch failed is not a test. Validating first also means
# a malformed lockfile costs nothing to reject.
echo "==> validating $lock"
if ! checksums="$(python3 -c '
import json, sys

try:
    lock = json.load(open(sys.argv[1]))
    grammar = lock["grammar"]
    sources = grammar["sources"]
    digests = grammar["sourceSha256"]
    include_dir = grammar["includeDir"]
    headers = grammar["headerSha256"]
except (OSError, ValueError, KeyError, TypeError) as exc:
    raise SystemExit("unreadable lockfile: %s" % exc)

if not isinstance(sources, list) or not sources:
    raise SystemExit("sources must be a non-empty list")
if not isinstance(digests, dict) or not digests:
    raise SystemExit("sourceSha256 must be a non-empty object")
if not isinstance(include_dir, str) or not include_dir:
    raise SystemExit("includeDir must be a non-empty string")
if not isinstance(headers, dict) or not headers:
    raise SystemExit("headerSha256 must be a non-empty object")

# The verified set and the compiled set must be the same set, in both
# directions. A digest with no corresponding source verifies a file nobody
# compiles; a source with no digest compiles a file nobody verified. Either
# way the two lists have drifted, and the gate no longer means what it says.
missing = [s for s in sources if s not in digests]
if missing:
    raise SystemExit("sourceSha256 has no entry for: " + ", ".join(missing))
extra = [d for d in digests if d not in sources]
if extra:
    raise SystemExit("sourceSha256 has entries for non-compiled files: "
                     + ", ".join(extra))

for name in sources:
    digest = digests[name]
    if not isinstance(digest, str) or len(digest) != 64:
        raise SystemExit("sourceSha256[%s] is not a sha256 digest" % name)
    if name.startswith("/") or ".." in name.split("/"):
        raise SystemExit("source path escapes the archive: %s" % name)
    print("c|" + name + "|" + digest)

# Headers are compiled in just as surely as the C sources: scanner.c includes
# tree_sitter/parser.h, and the compiler searches the include dir for it. An
# unverified header rewrites what the verified sources mean, so it gets the
# same digest treatment -- same path checks, same digest shape, and below, the
# same "the archive is the authority" set comparison.
prefix = include_dir.rstrip("/") + "/"
for name in sorted(headers):
    digest = headers[name]
    if not isinstance(digest, str) or len(digest) != 64:
        raise SystemExit("headerSha256[%s] is not a sha256 digest" % name)
    if name.startswith("/") or ".." in name.split("/"):
        raise SystemExit("header path escapes the archive: %s" % name)
    if not name.startswith(prefix):
        raise SystemExit("headerSha256[%s] is outside the include dir %s"
                         % (name, include_dir))
    print("h|" + name + "|" + digest)
' "$lock")"; then
  echo "error: cannot read pinned checksums from $lock" >&2
  echo "refusing to build an unverified parser" >&2
  exit 1
fi

if [ -z "$checksums" ]; then
  echo "error: no pinned checksums found in $lock" >&2
  echo "refusing to build an unverified parser" >&2
  exit 1
fi

tarball="$work/grammar.tar.gz"
# Fetch by immutable commit, not by tag: a tag can be moved, a commit cannot.
url="$repo/archive/$commit.tar.gz"
echo "==> fetching $repo @ $tag ($commit)"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tarball"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tarball" "$url"
else
  echo "error: neither curl nor wget is available" >&2
  exit 1
fi

src="$work/src"
mkdir -p "$src"
tar xzf "$tarball" -C "$src" --strip-components=1

# Verify the compiled sources by content, not the tarball: GitHub's archive
# bytes are not stable over time, but the file contents at a fixed commit are.
echo "==> verifying source checksums"
sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# Accumulate the compiler inputs from the SAME list that is being verified, so
# the verified set and the compiled set cannot diverge. Hardcoding the compiler
# arguments would let a lockfile that lists only parser.c pass every check and
# still compile scanner.c unverified -- and scanner.c is the hand-written
# external lexer, the part of a Tree-sitter grammar most worth tampering with.
compile_inputs=()
verified_headers=()
while IFS='|' read -r kind rel want; do
  [ -n "$rel" ] || continue
  case "$kind" in
    c) what=source ;;
    h) what=header ;;
    *) echo "error: unknown checksum record kind '$kind'" >&2
       echo "refusing to build an unverified parser" >&2
       exit 1 ;;
  esac
  if [ ! -f "$src/$rel" ]; then
    echo "error: pinned $what $rel missing from upstream archive" >&2
    echo "refusing to build an unverified parser" >&2
    exit 1
  fi
  got="$(sha_of "$src/$rel")"
  if [ "$got" != "$want" ]; then
    echo "error: checksum mismatch for $rel" >&2
    echo "  expected $want" >&2
    echo "  actual   $got" >&2
    echo "refusing to build an unverified parser" >&2
    exit 1
  fi
  echo "    ok $rel"
  if [ "$kind" = c ]; then
    compile_inputs+=("$src/$rel")
  else
    verified_headers+=("$rel")
  fi
done <<EOF_CHECKSUMS
$checksums
EOF_CHECKSUMS

if [ "${#compile_inputs[@]}" -eq 0 ]; then
  echo "error: no sources were verified" >&2
  echo "refusing to build an unverified parser" >&2
  exit 1
fi

if [ "${#verified_headers[@]}" -eq 0 ]; then
  echo "error: no headers were verified" >&2
  echo "refusing to build an unverified parser" >&2
  exit 1
fi

# Close the last way the verified set and the compiled set can diverge.
#
# Everything above keeps the lockfile internally consistent -- sources and
# sourceSha256 agree, and the compiler is handed exactly the verified list. But
# an internally consistent lockfile can still be WRONG about the grammar: drop
# scanner.c from both lists and every check above passes, while the parser is
# quietly built without its external lexer. scanner.c is hand-written C and the
# most attractive thing in a Tree-sitter grammar to tamper with, so "the
# lockfile agrees with itself" is not a strong enough invariant.
#
# The archive is the authority. Every C source it ships must be verified and
# compiled; a lockfile that omits one is rejected rather than silently building
# a different parser than the pin describes.
shipped="$(cd "$src" && find src -maxdepth 1 -name '*.c' | LC_ALL=C sort)"
declared="$(printf '%s\n' "${compile_inputs[@]#"$src/"}" | LC_ALL=C sort)"
if [ "$shipped" != "$declared" ]; then
  echo "error: pinned sources do not match the C sources in the archive" >&2
  echo "  archive ships: $(echo "$shipped" | tr '\n' ' ')" >&2
  echo "  lockfile pins: $(echo "$declared" | tr '\n' ' ')" >&2
  echo "refusing to build an unverified parser" >&2
  exit 1
fi

# The same invariant for headers, for the same reason.
#
# The compiler is handed -I "$src/$include_dir", so every header the archive
# ships under that directory is reachable from an #include in a verified source
# -- scanner.c includes tree_sitter/parser.h. Checksumming only the C files
# leaves the headers, which decide what those C files mean, entirely
# unverified. A shipped header with no digest is compiled without being
# checked; a digest for a header the archive does not ship verifies nothing.
shipped_headers="$(cd "$src" && find "$include_dir" -name '*.h' | LC_ALL=C sort)"
declared_headers="$(printf '%s\n' "${verified_headers[@]}" | LC_ALL=C sort)"
if [ "$shipped_headers" != "$declared_headers" ]; then
  echo "error: pinned headers do not match the headers in the archive" >&2
  echo "  archive ships: $(echo "$shipped_headers" | tr '\n' ' ')" >&2
  echo "  lockfile pins: $(echo "$declared_headers" | tr '\n' ' ')" >&2
  echo "refusing to build an unverified parser" >&2
  exit 1
fi

echo "==> compiling $out"
cc_bin="${CC:-cc}"
"$cc_bin" -shared -fPIC -O2 \
  -I "$src/$include_dir" \
  -o "$out" \
  "${compile_inputs[@]}"

# A library that does not export the entry point loads but yields zero matches,
# which is indistinguishable from "the code is clean". Fail loudly instead.
if command -v nm >/dev/null 2>&1; then
  if ! nm -D "$out" 2>/dev/null | grep -q " T $symbol$" \
     && ! nm -g "$out" 2>/dev/null | grep -q "$symbol"; then
    echo "error: $out does not export $symbol" >&2
    exit 1
  fi
fi

echo "==> built $out"
