# PowerShell rule fixtures

Fixtures for the rules in `rules-powershell/`, mirroring their directory layout
(`security/<rule-id>.yml`) exactly as `tests/` mirrors `rules/`. They are run by
`ast-grep test -c sgconfig.powershell.yml`, which resolves this directory
through the `testConfigs` entry in that config, with snapshots in
`__snapshots__/`.

Both are wired into `npm run test:powershell`, which also runs
`tests/test_powershell_parser.py`. That module carries the parser fail-closed
controls plus the inventory, diagnostic-text and severity-policy gates for this
pack — the equivalents under `tests/` glob `rules/` only and never see these
rules.

Running the suite requires the parser: `tools/powershell/build-grammar.sh`.
