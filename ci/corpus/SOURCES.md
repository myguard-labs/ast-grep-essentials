# Promotion corpus sources

Fixed false-positive and timing corpus for `ci/promote.py`. Every tree here is
either copied verbatim (non-test sources only) from a **public** MyGuard
repository or written for this corpus. Do not edit them in place; a change
alters the digest pinned in `ci/baselines/promotion.json` and requires a
reviewed rebaseline.

| Directory | Repository | Commit | License |
| --- | --- | --- | --- |
| `mailstrix/` | myguard-labs/mailstrix (`cmd/strixd`, `internal/cape`, `internal/atomicio`) | `367fba61f491daddf4b4c1da67a3a04c9bd4c5a8` | MIT, see `mailstrix/LICENSE` |
| `nginx-http-shield-module/` | myguard-labs/nginx-http-shield-module (`*.c`, `*.h`, `*.sh`) | `683ddb2f8b9576037f5fb6245f7c595c3b9b800a` | BSD-2-Clause, see `nginx-http-shield-module/LICENSE` |
| `samples/` | written for this corpus (C#, Java, JavaScript, Kotlin, PHP, Python, Ruby, Rust, Scala, Swift) | n/a | MyGuard, Thijs Eilander |

`samples/` holds small, realistic application files for languages the copied
repositories do not cover. Each file mixes safe idioms with a few deliberate
true positives, so a rule change shows up both as new noise on safe code and
as lost recall on the known findings. They are never built or run.

## Only public sources

A copied tree may only come from a repository that is public. The corpus ships
inside this public pack, so copying from a private repository would publish that
source — including into this repository's permanent git history, which a later
deletion does not undo.

`samples/python/` and `samples/php/` exist for that reason. Python and PHP
coverage previously came from two private repositories; those trees were
removed and replaced with purpose-written applications that keep the same
coverage shape — a safe majority that the Python and PHP rules must stay quiet
on, plus the deliberate findings the removed trees had produced.
