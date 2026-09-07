# Bake-off corpus

Parser-stress input for `tools/powershell/bakeoff.sh`, which counts `ERROR`
nodes per candidate grammar to produce the table in
[`docs/powershell-parser.md`](../../../docs/powershell-parser.md).

These files are **not** idiomatic PowerShell and are not meant to be. They exist
to exercise grammar edge cases, so linting them raises expected warnings that
must not be "fixed":

- `c05-mixedcase.ps1` deliberately uses `Invoke-Expression` and its `iex` alias
  to test mixed-case and alias command parsing. PSScriptAnalyzer flags both;
  that is the point of the file.
- Several files assign variables that are never read, because the assignment
  syntax is what is under test, not the dataflow.
- `c07-malformed.ps1` is intentionally unparsable. It is the negative control:
  a grammar reporting *zero* errors on it would be the suspicious result.

`p01`..`p05` are single-line probes for the three known ecosystem failure shapes
(`--`, `./path`, `--flag=value`) plus a clean-parse control.

Editing these files changes the recorded error counts. If you do, re-run
`tools/powershell/bakeoff.sh` and update the table in the docs.
