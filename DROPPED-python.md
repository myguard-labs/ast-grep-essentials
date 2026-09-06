# Dropped Python candidates

Each of these needs information a syntactic matcher does not have, and no
precise syntactic sub-claim was left once the dataflow part was removed.

- **6 py-flask-send-file-user-path** — the interesting form is `send_file(os.path.join(base, <user>))`; the direct `send_file(request...)` shape is already shipped as `py-open-request-arg`, and the `os.path.join` wrapper form needs to know whether a later `realpath` prefix check guards it.
- **7 py-os-path-join-request** — `os.path.join` with a request leaf is only a defect when nothing sanitises it before use; the sanitising call and the use are separate statements, so the claim needs dataflow.
- **20 py-urlopen-user-url** — the `urlopen` sink with an interpolated URL is already matched by the existing `py-ssrf-request-fstring`, whose `urlopen-function` utility covers both the bare and the qualified spelling; a plain-variable variant would need taint to be worth shipping.
- **29 py-langchain-unsafe-tools** — the shipped part is `allow_dangerous_code=True` style keywords, but the rest of the claim (a `loads` from `langchain_core.load`, an unsandboxed REPL tool) turns on which module the bare name came from and whether the surrounding agent is sandboxed.
- **36 py-regex-nested-quantifier** — deciding catastrophic backtracking is automata analysis, not pattern matching; a regex-over-regex approximation produces both misses and false positives and belongs in a tool such as `regexploit`.
- **38 py-socket-recv-unbounded** — the defect is a length read from the wire and used without an intervening bound check, which requires tracking the value across statements and into helper functions.
