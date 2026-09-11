# astgrep-rules

Curated [ast-grep](https://ast-grep.github.io/) rules for Bash, C, C++, C#,
Go, HTML, Java, JavaScript, Kotlin, Lua, PHP, Python, Ruby, Rust, Scala, Swift,
and TypeScript. C includes nginx-domain rules. Security and correctness checks
identify code that needs review; a match alone does not establish a
vulnerability.

Perl is also present in the MyGuard corpus, but ast-grep 0.45.3 has no built-in
Perl parser. [Custom-language support](https://ast-grep.github.io/advanced/custom-language.html)
requires a separately compiled, platform-specific tree-sitter shared library
and remains experimental upstream, so Perl files are deliberately not parsed
through another language. Use a Perl analyzer until that parser and its
consumer-discovery contract are packaged and tested on every supported
platform.

## Layout

- `rules/<parser-language>/<category>/`: active YAML rules. nginx rules use the
  C parser and `nginx-*` IDs; generic C rules use `c-*` IDs. Disabled aliases
  may retain a former ID for compatibility.
- `tests/<language>/<category>/`: matching `valid` and `invalid` fixtures.
- `docs/`: authoring guidance, detection limits, per-rule source evidence, and
  excluded candidates with rejection evidence.

Rule IDs are stable across directory changes. Intentional ID changes are listed
in [ID migrations](docs/id-migrations.md); consumers must apply those mappings
when updating the pack.

The active pack includes 184 rules copied from
[CodeRabbit's ast-grep essentials](https://github.com/coderabbitai/ast-grep-essentials)
at commit `73120109bf45c284d0cd8a37bdd7082e80e92e87`. Git attributes their original
creation to ESS-ENN. The upstream root `LICENSE` is Apache License 2.0; each
copied rule carries that license notice and an exact source link, and the
import is tracked in
[`docs/coderabbit-rules.json`](docs/coderabbit-rules.json).

The disabled compatibility alias for a renamed rule preserves an explicitly
promoted former ID only. Consumers must still migrate suppressions, overrides,
filters, and reports; promoting the alias temporarily emits both the former and
replacement IDs, as detailed in the migration ledger.

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

Migration: consumers that previously configured the parent `rules/` directory
must replace it with the native-language `ruleDirs` listed in `sgconfig.yml`
before updating this checkout. The parent now contains `rules/powershell/`,
whose rules cannot load without the custom language registration in
`sgconfig.powershell.yml`; leaving the parent configured makes the entire native
scan fail. Paths are relative to the consuming config. Keep tests and
`docs/candidates` out of rule discovery. Project-config settings do not follow a
`ruleDirs` import: consumers that scan PHP templates must also copy this
repository's `languageGlobs` PHP mapping (`php: ['*.php', '*.phtml']`) so both
extensions use the PHP parser.

Warnings and information are advisory; error severity can fail a scan. Validate
any promoted rule IDs and exercise a known positive before using a scan as a gate.

See [authoring](docs/authoring.md), [ID migrations](docs/id-migrations.md),
[nginx classification](docs/nginx-classification.md), [limitations](docs/limitations.md),
[sources](docs/sources.md) and [rejected candidates](docs/rejected-candidates.md).

## License

The [MyGuard Internal Use License 1.0](LICENSE) permits internal use, including
internal commercial use. Outside GitHub, distribution to third parties is
prohibited. GitHub users retain applicable on-service rights, and the license
defines a limited fork and branch workflow for pull-request contributions.

## Related reading

[The MyGuard AI coding workflow](https://deb.myguard.nl/articles/ai-coding-workflow-memory-skills-review/)
describes how this rule pack is authored and reviewed: fixture pairs and near
misses, the discovery check that keeps a rule reachable, how severity is chosen,
and the semantic limits that decide which candidates are rejected outright.
