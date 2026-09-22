# astgrep-rules

[ast-grep security rules pack](https://deb.myguard.nl/articles/ast-grep-security-rules-pack/)

Public, curated ast-grep security and correctness rules with their fixtures,
scan configuration, licenses, and a pinned ast-grep engine. Rule creation,
enrichment, planning, and validation tooling live in the private MyGuard
harness.

The pack covers Bash, C, C++, C#, Go, HTML, Java, JavaScript, Kotlin, Lua, PHP,
Python, Ruby, Rust, Scala, Swift, and TypeScript, including checks for nginx
code. A match identifies code that deserves review; it does not by itself prove
that the code is vulnerable.

## Run a scan

Install the pinned engine and scan a source tree:

```sh
npm ci
npx ast-grep scan -c sgconfig.yml /path/to/source
```

Warnings and informational findings are advisory. Verify a rule ID against
known positive and negative examples before making it block commits or CI.

Native rules live under `rules/<language>/<category>/<id>.yml`; matching YAML
fixtures live under `tests/<language>/<category>/<id>.yml`. Import the explicit
native-language `ruleDirs` from `sgconfig.yml`, not the parent `rules/`
directory. The latter also contains PowerShell rules, which require the custom
parser configured separately in `sgconfig.powershell.yml`.

For PHP consumers, copy the `languageGlobs` mapping too, so both `.php` and
`.phtml` files use the PHP parser. The pinned ast-grep release has no built-in
Perl parser, so this pack does not parse Perl as another language.

## Contribute a rule

A rule change should contain one stable, globally unique rule ID and its YAML
fixture. Fixtures need positive examples, near misses, comment and string
lookalikes, and relevant boundary cases. Keep every example inert: validation
parses fixtures and never needs to execute them.

Rule enrichment uses one pull request per rule ID. A rule PR may include that
rule's fixture and snapshot, but never a second rule. MyGuard runs the private
authoring and validation harness before merging changes to this public corpus.

## Rule sources

The active pack incorporates 184 rules from
[CodeRabbit's ast-grep essentials](https://github.com/coderabbitai/ast-grep-essentials),
copied at commit `73120109bf45c284d0cd8a37bdd7082e80e92e87`. That upstream
project is now archived and no longer maintained, so those rules are carried
forward here.

The incorporated rules remain under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), and the
upstream license text is retained verbatim at
[`LICENSES/CodeRabbit-ast-grep-essentials-Apache-2.0.txt`](LICENSES/CodeRabbit-ast-grep-essentials-Apache-2.0.txt).
Each incorporated rule records its exact upstream source, its Apache-2.0
notice, and any MyGuard modification in its leading comments and `metadata`
block. Rules original to this pack are covered by the repository license
described below.

## License

The [MyGuard Internal Use License 1.0](LICENSE) permits internal use, including
internal commercial use. Outside GitHub, distribution to third parties is
prohibited. GitHub users retain applicable on-service rights, and the license
defines a limited fork and branch workflow for pull-request contributions.
