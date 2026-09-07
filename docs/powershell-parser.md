# PowerShell parser selection and integration

PowerShell is not one of ast-grep's built-in languages. Supporting it means
choosing a Tree-sitter grammar, compiling it to a dynamic library, and
registering it as a custom language. This document records which grammar was
chosen and why, what the parser does and does not handle, and how to update it.

## Toolchain prerequisite

Custom languages need ast-grep **0.45.3**, which this repository pins in
`package.json`. Note that a system-wide `ast-grep` earlier on `PATH` may shadow
it -- 0.45.2 was observed doing exactly that, and it rejects `--lang powershell`
outright. Every command below, and every test, invokes
`node_modules/.bin/ast-grep` explicitly for that reason.

## Selected grammar

| | |
| --- | --- |
| Grammar | [wharflab/tree-sitter-powershell](https://github.com/wharflab/tree-sitter-powershell) (`tree-sitter-pwsh`) |
| Pinned tag | `v0.38.1` |
| Pinned commit | `b783f6375530f632cbbb5bc411d333593f541ae7` |
| License | MIT |
| Tree-sitter ABI | 14 (`LANGUAGE_VERSION` in `src/parser.c`) |
| Exported symbol | `tree_sitter_powershell` |

The pin, both source checksums and the rejected-grammar record live in
[`tools/powershell/grammar.lock.json`](../tools/powershell/grammar.lock.json).

## Bake-off

Parser acceptance is a security boundary. A grammar that mis-parses a construct
does not report an error we would notice -- it produces an `ERROR` node whose
subtree the rules cannot match, so the affected code is silently *not scanned*.
Selection was therefore driven by parse-error counts, not by feature lists.

Both candidates were compiled from their pinned releases with the same
`gcc -shared -fPIC -O2` invocation and scanned with an `ERROR`-kind rule.
`MISSING` is not a matchable kind in ast-grep, so `ERROR` node counts are the
measure.

`ERROR` nodes per corpus file, lower is better:

| Corpus file | Covers | Airbus v0.26.5 | **Wharflab v0.38.1** |
| --- | --- | ---: | ---: |
| `c01-basics-51.ps1` | PowerShell 5.1: `param`, `CmdletBinding`, loops, hashtables, `try`/`catch`/`finally`, `switch` | 1 | **1** |
| `c02-ps7.ps1` | PowerShell 7+: `??`, `?.`, `??=`, ternary, `ForEach-Object -Parallel`, `class`, `enum` | 8 | **4** |
| `c03-herestring.ps1` | Expandable and literal here-strings, embedded terminator lookalike | 0 | **0** |
| `c04-splat.ps1` | Hashtable and array splatting, splat plus explicit parameter | 0 | **0** |
| `c05-mixedcase.ps1` | `INVOKE-EXPRESSION`, `get-childitem`, `Write-HOST`, `iex`, static member access | 0 | **0** |
| `c06-native-args.ps1` | Native command arguments: `git`, `npm`, `docker`, `kubectl`, `cmd.exe`, quoted paths | 7 | **3** |
| `c07-malformed.ps1` | Deliberately malformed input (negative control -- errors are *expected* here) | 2 | **2** |
| **Total** | | **18** | **10** |

Re-derive this table at any time with
[`tools/powershell/bakeoff.sh`](../tools/powershell/bakeoff.sh), which compiles
both candidates from their pinned commits and counts errors over the corpus
checked in at `tools/powershell/bakeoff-corpus/`. Including the command-shape
probes below, the totals are **12** for Wharflab against **27** for Airbus.

Wharflab was selected: it halves the error count on PowerShell 7+ syntax and on
native-command arguments, and it is never worse on any corpus file. This
reproduces the claimed broader 7+ coverage rather than taking it on trust.

### Security-boundary command shapes

These three shapes are known ecosystem failure points. Each was probed as an
isolated one-line script:

| Probe | Airbus | **Wharflab** |
| --- | ---: | ---: |
| `git log -- path/to/file` | 2 errors | **1 error** |
| `./script.ps1 -Arg 1` | 2 errors | **0 errors** |
| `npm install --flag=value` | 2 errors | **0 errors** |
| `./build/run.sh --config=/etc/a.conf` | 3 errors | **1 error** |
| `Get-ChildItem -Path .` (control) | 0 errors | **0 errors** |

Wharflab parses `./path` and `--flag=value` cleanly; Airbus fails all three
shapes. This was the decisive result.

**Residual limitation:** the bare `--` end-of-options separator still produces an
`ERROR` node in Wharflab. A command invocation containing `--` is therefore not
reliably matchable, and rules must not assume coverage of it. Tracked in
[`limitations.md`](limitations.md).

## Rejected grammars

**[airbus-cert/tree-sitter-powershell](https://github.com/airbus-cert/tree-sitter-powershell)
v0.26.5** (commit `d398441825243b00e317e87e1829b9d6a3e54ce0`, MIT, Tree-sitter
ABI 15). Rejected on measured evidence: 18 `ERROR` nodes against Wharflab's 10
over the same corpus, and failure on all three security-boundary command shapes.
Its newer ABI does not compensate for parsing less of the language.

**[PowerShell/tree-sitter-PowerShell](https://github.com/PowerShell/tree-sitter-PowerShell)**.
Rejected without probing: the repository is archived upstream and the grammar is
incomplete. Adopting an unmaintained parser for a security boundary is not
defensible regardless of how it benchmarks today.

## Integration

The PowerShell pack lives in its own config,
[`sgconfig.powershell.yml`](../sgconfig.powershell.yml), **not** in
`sgconfig.yml`.

This is deliberate and is enforced by a test. ast-grep aborts the *entire* scan
when a registered custom language cannot be loaded -- it does not skip only that
language. Registering PowerShell in the main config would convert a missing
optional parser into a hard failure of all 248 native-language rules for every
consumer that never wanted PowerShell:

```console
$ ast-grep scan -c sgconfig.yml rules/python     # with powershell registered, library absent
Error: Cannot load custom language library
$ echo $?
79
```

Keeping the configs separate means the default scan is unaffected by whether the
grammar has been built, while a PowerShell scan whose parser is unusable still
fails closed rather than reporting zero findings.

### File extensions

`.ps1`, `.psm1` and `.psd1` are registered.

`.psd1` was gated on separate parse evidence rather than assumed. PowerShell
data files are a hashtable-literal subset of the script grammar, and a module
manifest plus a `ConvertFrom-StringData` localization file both parsed with
**zero** `ERROR` nodes. Upstream's own `tree-sitter.json` lists `psd1` among its
file types, corroborating the measurement. `tests/test_powershell_parser.py`
pins this with `test_psd1_manifest_parses_without_error_nodes`, so a future
grammar bump that regresses data-file parsing fails the suite rather than
quietly degrading `.psd1` coverage.

`.pssc` and `.psrc` are not registered: upstream lists them, but no parse
evidence was gathered for them here, and this repository has no rules that
target them.

### Metavariable sigil

`expandoChar` is `µ`.

ast-grep's default `$VAR` metavariable syntax collides with PowerShell, where
`$` introduces every ordinary variable. `_` -- the value used in ast-grep's own
documentation example -- is a poor choice for PowerShell specifically, because
`$_` is the pipeline variable and appears in almost every script; a sigil that
can occur in real source risks a pattern's literal text being read as a
metavariable. `µ` is not valid in a PowerShell variable name or command token,
so it cannot collide.

Both spellings work in patterns: `Invoke-Expression $A` and
`Invoke-Expression µA` bind the same metavariable.

### Building the parser

```sh
tools/powershell/build-grammar.sh
ast-grep scan -c sgconfig.powershell.yml path/to/scripts
```

The library is built, not vendored, and `build/` is git-ignored. The script:

1. **validates the lockfile before fetching anything**, so a malformed pin
   costs nothing to reject and the gate does not depend on the network being
   up. It refuses when the checksum list cannot be read, is empty, is wrongly
   typed, or does not cover exactly the sources it will compile -- in both
   directions, so neither an unverified source nor a digest for a file nobody
   compiles can slip through;
2. fetches the grammar by **immutable commit hash**, not by tag -- a tag can be
   moved, a commit cannot;
3. verifies the SHA-256 of each source against `grammar.lock.json` and
   **refuses to build on a mismatch**. Checksums are over `src/parser.c` and
   `src/scanner.c` rather than the tarball, because GitHub's archive bytes are
   not stable over time while file contents at a fixed commit are;
4. **hands the compiler exactly the list it verified**, accumulated during
   verification rather than hardcoded, so a file that was not verified cannot
   be compiled. It then requires that the verified set equals every C source
   the extracted archive ships. An internally consistent lockfile can still be
   wrong about the grammar -- dropping `scanner.c` from both lists passes every
   internal check while building a parser with no external lexer -- so the
   archive, not the lockfile, is the authority on what must be verified;
5. compiles to the platform-native suffix -- `.so` on Linux, `.dylib` on macOS,
   `.dll` on Windows -- resolved from `uname`;
6. asserts the built library exports `tree_sitter_powershell`. A library missing
   its entry point loads but matches nothing, which is indistinguishable from
   clean code.

It needs a C compiler (`cc`, or `$CC`), `python3`, and `curl` or `wget`. It does
**not** need the Tree-sitter CLI, so it works in minimal CI images.

There is no cross-compilation and no prebuilt artifact: upstream publishes no
release binaries, and each platform builds its own library from the same pinned,
checksum-verified sources.

### Platform support, and what is actually verified

`sgconfig.powershell.yml` maps `libraryPath` by **Rust target triple**, which
ast-grep resolves against its own host target, because the build script emits
the platform-native suffix and a single hardcoded path would build one artifact
and look for another:

```yaml
libraryPath:
  x86_64-unknown-linux-gnu: build/powershell/powershell.so
  aarch64-apple-darwin: build/powershell/powershell.dylib
  x86_64-pc-windows-msvc: build/powershell/powershell.dll
```

**Only `x86_64-unknown-linux-gnu` is verified.** That is the platform this
repository's CI runs on and the only one where the build, the load and the
controls have actually been executed. The macOS and Windows entries are declared
and the build script handles their suffixes, but no artifact has been built or
loaded on those platforms here — treat them as untested until someone runs
`tools/powershell/build-grammar.sh` and the suite on that host.

Two properties make that honest rather than a silent gap:

* A target triple absent from the map, or present with an unloadable path, is a
  **fail-closed** error: ast-grep reports `Cannot load custom language library`
  and exits non-zero. It does not scan zero files and report success.
* `tests/test_powershell_parser.py` fails — it does not skip — when a grammar
  artifact exists but does not match the running host. The parser-dependent
  tests are skipped only when nothing was built at all, so a successful build on
  an unverified platform cannot produce a green suite that verified nothing.

### Updating the grammar

1. Pick the new upstream tag and resolve it to a commit hash.
2. Update `tag`, `commit` and both `sourceSha256` entries in
   `tools/powershell/grammar.lock.json`. Compute the hashes from the extracted
   archive; do not copy them from an unverified source.
3. Re-check `treeSitterAbi` against `LANGUAGE_VERSION` in `src/parser.c`.
4. Rebuild and run `python3 -m unittest tests.test_powershell_parser`. A skip
   here means no artifact was built; a *failure* naming a suffix mismatch means
   one was built for a different platform.
5. Re-run the bake-off corpus if the update is a major version, and update the
   error-count table above.

## Rule authoring constraints

`$A -gt 1` does **not** match a comparison expression. In isolation, Tree-sitter
parses it as a *command* named `$A` with `-gt` as a command parameter:

```text
command
  MetaVar $A
  command_elements
    command_parameter -gt
    ...
```

This is inherent to PowerShell's grammar, where a bare token at statement
position is a command invocation. Command-shaped patterns
(`Invoke-Expression $A`, `Get-ChildItem`) match reliably and cover the intended
rule families; expression-shaped rules need a `kind:` anchor
(`kind: comparison_expression`) rather than a bare pattern.
