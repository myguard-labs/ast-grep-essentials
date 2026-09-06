# astgrep-rules

Handcrafted [ast-grep](https://ast-grep.github.io/) rules for Bash, C/nginx, Go,
Java, JavaScript, Lua, PHP, and Python. Security and correctness checks identify
code that needs review; a match alone does not establish a vulnerability.

Perl is also present in the MyGuard corpus, but ast-grep 0.45.2 has no built-in
Perl parser. [Custom-language support](https://ast-grep.github.io/advanced/custom-language.html)
requires a separately compiled, platform-specific tree-sitter shared library
and remains experimental upstream, so Perl files are deliberately not parsed
through another language. Use a Perl analyzer until that parser and its
consumer-discovery contract are packaged and tested on every supported
platform.

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
out of rule discovery. Project-config settings do not follow a `ruleDirs`
import: consumers that scan PHP templates must also copy this repository's
`languageGlobs` PHP mapping (`php: ['*.php', '*.phtml']`) so both extensions use
the PHP parser.

Warnings and information are advisory; error severity can fail a scan. Validate
any promoted rule IDs and exercise a known positive before using a scan as a gate.

See [authoring](docs/authoring.md) and [limitations](docs/limitations.md).
