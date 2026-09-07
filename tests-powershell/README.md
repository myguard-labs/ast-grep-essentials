# PowerShell parser integration tests

These are driven by `tests/test_powershell_parser.py`, not by `ast-grep test`.
The `testConfigs` entry in `sgconfig.powershell.yml` points here so that rule
fixtures added by later work land in this directory rather than mixing with the
native-language suites under `tests/`.
