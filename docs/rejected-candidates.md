# Rejected candidates

Candidates from the 2026 harvest that were researched and not shipped, with the
reason each was rejected. Every entry needs information a syntactic matcher does
not carry: dataflow, declared types, reachability, or cross-function state. They
are recorded so the same ground is not re-mined. Entries are grouped by the
language whose rules they would have joined.

## c and nginx

- `c-mktemp-tmpnam` — already shipped as `c-insecure-temp-name`, which matches
  the same four API names with the same call-name matcher.
- `c-signed-length-compare` — the claim depends on the declared type of the
  compared variable, which the matcher cannot read from a parameter list without
  also matching every unsigned comparison; no precise syntactic sub-claim
  survives the reduction.
- `nginx-escape-uri-two-pass-mismatch` — the real defect pairs a sizing call in
  a length handler with a copy call in a separate copy handler, so the two calls
  are never in one syntactic scope; the same-function reduction only restates
  the shipped `nginx-escape-uri-alloc-without-double`.
- `nginx-regex-captures-unnamed-before-alloc` — requires knowing which regex
  last populated `r->captures`, which is cross-function state.
- `nginx-pnalloc-buffer-uninitialized-len` — needs the byte count actually
  written, a dataflow fact; `b->last = b->end` alone is correct whenever the
  buffer was filled.
- `nginx-cpymem-unbounded` — the claim is that the copied length exceeds the
  destination capacity, which is arithmetic reasoning, not syntax.
- `nginx-subrequest-ctx-on-r-not-main` — most filters legitimately operate per
  subrequest; the absence of an `r != r->main` test is not a defect.
- `nginx-ctx-stores-buf-from-in-chain` — whether the saved buffer outlives the
  call depends on the buffer's ownership flags, which syntax cannot read.
- `nginx-main-count-increment-without-done` — the balancing decrement is
  routinely in a callback in another function, so the co-occurrence check is not
  a claim.
- `nginx-finalize-after-send-header-fallthrough` — subsumed by the shipped
`nginx-finalize-plus-return-rc`, which states the precise sibling-statement
shape.
- `nginx-http-status-from-variable-getter` — the `not_found` half is a
  co-occurrence heuristic and the status half is already covered by the shipped
  `nginx-conf-return-code-confusion` family.
- `nginx-pfree-non-large` — depends on the pool's `max`, a runtime value.
- `nginx-atoi-result-used-as-length` — needs the declared type of the receiving
  variable to distinguish the defect from correct signed handling.
- `nginx-header-value-len-zero-deref` — the guard may be any earlier length test
  in the function or in the caller; absence of a local comparison is not a
  defect.
- `c-double-free-cleanup-no-null` — a single-owner destructor that frees a field
  without nulling it is correct; the claim needs reachability, not syntax.
- `c-callback-frees-owner-then-uses` — reduced and shipped as the precise
`nginx-use-after-finalize`; the generic multi-destructor form has no such shape.
- `nginx-conf-string-injected-into-protocol` — requires knowing whether the
  value was validated earlier, which is dataflow across the parser.

## go

- **go-exec-arg-injection** (harvest 13): deciding whether an argument is
  option-injectable needs per-binary flag semantics and the position of a `--`
  terminator relative to a value whose origin is only known by dataflow; the
  syntactic residue is `exec.Command` with a non-literal argument, which is
  noise on every well-written call site.
- **go-url-parse-scheme-hostcheck-ssrf** (harvest 14, guard tier): the claim is
  that a scheme or prefix test is the *sole* SSRF guard. Sole-ness is a
  whole-function property over branches and helper calls, not a syntactic one.
  The precise half of the candidate — a request accessor passed straight to an
  outbound fetch — ships as `go-http-request-url-ssrf`.
- **go-handler-no-recover-goroutine** (harvest 28): requires knowing that the
  enclosing function is reached as an HTTP handler and that no wrapper in the
  goroutine's call graph recovers. Both are reachability facts; the syntactic
  version fires on every `go func()` in a file that imports `net/http`.
- **go-json-decode-into-interface** (harvest 11, second smell): distinguishing a
  decode into `map[string]any` from one into a concrete type requires resolving
  the declared type of the destination variable, which is type information the
  matcher does not have.
- **go-aes-gcm-random-nonce-longlived-key** (harvest 17, Pion tier): the defect
  is a birthday bound over how many messages one key encrypts. That is a
  protocol lifetime property with no syntactic signature; only the fixed and
  never-randomised nonce subset ships, as `go-aes-gcm-static-nonce`.
- **go-jwt-keyfunc-no-method-check** (harvest 20, tier b): a key function that
  validates the algorithm via a shared helper is indistinguishable from one that
  skips the check, because the check may live behind any call. Only the
  unverified-parse and none-algorithm tier ships, as `go-jwt-unverified`.

## php and wordpress

- wp-delete-file-from-attached-meta (#11): needs the `get_post_meta(...,
  '_wp_attached_file')` result to flow through a variable into the delete sink;
  syntax cannot link the two statements.
- wp-esc-sql-unquoted (#8): deciding whether an escaped value lands inside SQL
  quotes requires reasoning about the concatenated string built across operands
  and variables, not a single syntactic shape.
- wp-wpdb-like-without-esc-like (#9): the injection arm restates
  php-sql-string-interp; the remaining `%s` arm needs the bound value's
  provenance, which is dataflow.
- wp-nonce-localized-publicly (#17): the enclosing enqueue hook name is only
  visible when the callback is an inline closure, so the claim is not syntactic
  in the common (named-callback) case.
- wp-sanitize-text-field-as-path-guard (#22): the sanitizer and the filesystem
  sink are almost always separate statements joined by a variable; the
  direct-wrapper form alone is too narrow to be worth a rule.
- php-eval-call (#24): already covered — php-exec-sink's function regex includes
  `eval`.
- php-assert-non-literal (#27): already covered — php-exec-sink's function regex
  includes `assert`.
- php-http-host-in-mail (#32): the poisoned link is built in one statement and
  mailed in another; linking them needs dataflow.
- php-unserialize-allowed-classes-true (#38): redundant — php-unserialize fires
  on every `unserialize` call regardless of the options argument.
- php-uniqid-as-token (#31): `uniqid` is already in php-weak-crypto's function
  regex, so every call site is reported there already.
- php-strip-tags-as-xss-guard (#37): redundant — php-echo-superglobal-xss does
  not list `strip_tags` as an encoder, so it already reports `echo
  strip_tags($_GET[...])`; verified by scanning that fixture with the existing
  rule.

## python

- **6 py-flask-send-file-user-path** — the interesting form is
  `send_file(os.path.join(base, <user>))`; the direct `send_file(request...)`
  shape is already shipped as `py-open-request-arg`, and the `os.path.join`
  wrapper form needs to know whether a later `realpath` prefix check guards it.
- **7 py-os-path-join-request** — `os.path.join` with a request leaf is only a
  defect when nothing sanitises it before use; the sanitising call and the use
  are separate statements, so the claim needs dataflow.
- **20 py-urlopen-user-url** — the `urlopen` sink with an interpolated URL is
  already matched by the existing `py-ssrf-request-fstring`, whose
  `urlopen-function` utility covers both the bare and the qualified spelling; a
  plain-variable variant would need taint to be worth shipping.
- **29 py-langchain-unsafe-tools** — the shipped part is
  `allow_dangerous_code=True` style keywords, but the rest of the claim (a
  `loads` from `langchain_core.load`, an unsandboxed REPL tool) turns on which
  module the bare name came from and whether the surrounding agent is sandboxed.
- **36 py-regex-nested-quantifier** — deciding catastrophic backtracking is
  automata analysis, not pattern matching; a regex-over-regex approximation
  produces both misses and false positives and belongs in a tool such as
  `regexploit`.
- **38 py-socket-recv-unbounded** — the defect is a length read from the wire
  and used without an intervening bound check, which requires tracking the value
  across statements and into helper functions.

## javascript

- `js-path-join-request` — the `startsWith` containment guard is a separate
  statement, so the rule would flag every correctly guarded `path.join`; needs
  dataflow.
- `js-buffer-constructor-or-proto-key` (merge half) — a prototype-pollution
  guard lives inside the callee, invisible at the call site; needs dataflow. The
  `new Buffer(x)` half is a deprecation, not a defect the matcher can establish.
- `js-nosql-query-from-body` — distinguishing an operator-injectable
  whole-object argument from a scalar property requires type information about
  the request value; needs dataflow.
- `js-postmessage-no-origin-check` — the origin check is routinely done in a
  called helper, and `postMessage(x, '*')` with non-secret data is a legitimate
  pattern; the syntactic sub-claim would be mostly false positives.

## java

- `java-file-path-from-request` — the `normalize()` plus `startsWith` zip-slip
  guard is a following statement, so a correctly guarded extraction would be
  flagged; needs dataflow.
- `java-url-open-from-request` — allowlist enforcement lives in a wrapper call
  the matcher cannot follow; needs dataflow.
- `java-reflection-from-request` (the `@RequestParam` half) — tracing a handler
  parameter to a sink needs dataflow; the direct-expression half shipped as
  `java-expression-eval-dynamic`.
- `java-log-injection-lookup` — parameterised logging is the correct form and
  must not be flagged, while the concat form is indistinguishable from ordinary
  message building; the useful residue shipped as
  `java-format-string-not-literal`.
- `java-android-webview-unsafe` — the risky combination is
  `setJavaScriptEnabled` together with `addJavascriptInterface` across a class,
  and the individual settings are version-gated by `minSdk`, which is not in the
  file.
- `java-response-reflect` (XSS half of the composite candidate) — an escaping
  wrapper is recognisable only by name and the writer receiver is unconstrained,
  so the arm would fire on ordinary text output; the redirect half shipped as
  `java-response-open-redirect`.

## lua

- `lua-dynamic-load-string` — `load`, `loadstring` and `dofile` are already
  covered by the existing `lua-execution-sink`; the residual `setfenv` and
  `debug.*` surface is a sandbox-construction idiom, not a defect on its own.
- `lua-shared-dict-check-then-set` — proving a check-then-set race needs the
  same key expression in two statements plus the absence of a lock anywhere in
  the request path; needs dataflow.
- `lua-cookie-or-log-secret` — the cookie half requires knowing that flags were
  not appended elsewhere in the built string, and the log half is a pure name
heuristic over arbitrary arguments; both would be dominated by false positives.
- `lua-http-client-user-url` (SSRF half of the composite candidate) — the
  request-derived URL reaches the client through a variable in every realistic
  handler; needs dataflow. The `ssl_verify = false` half shipped as
  `lua-http-client-verify-disabled`.

## bash

- `sh-unquoted-variable-in-destructive-cmd` — deliberate word splitting
  (`gcc $CFLAGS`) is idiomatic and the command allowlist would have to be
  open-ended; ShellCheck SC2086 already owns this lens with a shell-aware
  parser.
- `sh-read-without-r-or-ls-loop` — `find | xargs` without `-print0`/`-0` is a
pipeline-shape claim whose safe variants are numerous, and `read -r` is already
  ShellCheck SC2162; no additional signal here.
- `sh-toctou-test-then-act` — requires metavariable equality between the test
  operand and the action operand plus path classification; the shell grammar
  gives no reliable binding across the `&&`, so the matcher would be
  approximate.
- `sh-destructive-device-or-system-write` — `dd of=/dev/sda` and `mkfs` on a
  variable are intentional in every imaging and installer script, so the finding
  would be advisory noise rather than a defect claim.
- `sh-gh-actions-expression-in-run` — the `${{ ... }}` token lives in workflow
  YAML, not in a shell file; expressing it needs the YAML grammar and a
  `run:`-scalar extraction step that this pack does not have.
- `sh-download-then-execute` (chmod-then-run half) — correlating `curl -o X`
  with a later `chmod +x X` and an execution of `X` needs a multi-statement
  window with metavariable reuse across commands; the process-substitution and
  here-string forms shipped as `sh-process-substitution-shell-input`, and the
  archive forms as `sh-archive-extract-to-system-root`.
