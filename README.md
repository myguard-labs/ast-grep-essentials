# astgrep-rules

Handcrafted [ast-grep](https://ast-grep.github.io/) rules for Bash, C/nginx, Go,
PHP, and Python. Security and correctness checks identify code that needs review;
a match alone does not establish a vulnerability.

## Layout

- `rules/<language>/<category>/`: active YAML rules; nginx rules use `c`.
- `tests/<language>/<category>/`: matching `valid` and `invalid` fixtures.
- `docs/`: authoring guidance and excluded candidates with rejection evidence.

Rule IDs are stable across directory changes. Third-party packs are maintained
separately by consumers and are not bundled here.

## Test

```sh
npm ci
python3 -m pip install -r requirements-dev.txt
npm test
```

Tests check rule/test coverage, positive detections, negative controls, and
snapshots. To review changed snapshots, run `npx ast-grep test -i` and inspect
the resulting diff. CI never accepts snapshots automatically.

## Use

```sh
npx ast-grep scan -c sgconfig.yml /path/to/source
```

Consumers can add this checkout's `rules` directory to their `sgconfig.yml`
`ruleDirs`; paths are relative to that config. Keep tests and `docs/candidates`
out of rule discovery.

Warnings and information are advisory; error severity can fail a scan. Validate
any promoted rule IDs and exercise a known positive before using a scan as a gate.

See [authoring](docs/authoring.md) and [limitations](docs/limitations.md).
