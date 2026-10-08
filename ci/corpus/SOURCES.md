# Promotion corpus sources

Fixed false-positive and timing corpus for `ci/promote.py`. Files are copied
verbatim (non-test sources only) from these MyGuard repositories, except
`samples/`, which is written for this corpus. Do not edit
them in place; a change alters the digest pinned in
`ci/baselines/promotion.json` and requires a reviewed rebaseline.

| Directory | Repository | Commit | License |
| --- | --- | --- | --- |
| `codeshrike/` | myguard-labs/codeshrike (`*.py`) | `4c5bea8a27ccfd74da1a8ab196003b77b701fa4d` | MyGuard, Thijs Eilander |
| `database-boost/` | myguard-labs/database-boost (`*.php`) | `b6e79427c89efc674247c89bdd4af41eea05bebc` | MyGuard, Thijs Eilander |
| `mailstrix/` | myguard-labs/mailstrix (`cmd/strixd`, `internal/cape`, `internal/atomicio`) | `367fba61f491daddf4b4c1da67a3a04c9bd4c5a8` | MIT, see `mailstrix/LICENSE` |
| `nginx-http-shield-module/` | myguard-labs/nginx-http-shield-module (`*.c`, `*.h`, `*.sh`) | `683ddb2f8b9576037f5fb6245f7c595c3b9b800a` | BSD-2-Clause, see `nginx-http-shield-module/LICENSE` |
| `samples/` | written for this corpus (Java, Kotlin, Ruby, Rust, Scala, Swift, C#, JavaScript) | n/a | MyGuard, Thijs Eilander |

`samples/` holds small, realistic application files for languages the copied
repositories do not cover. Each file mixes safe idioms with a few deliberate
true positives, so a rule change shows up both as new noise on safe code and
as lost recall on the known findings. They are never built or run.
