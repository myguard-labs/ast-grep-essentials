# Rejected candidates

Candidates from the 2026 harvest that were researched and not shipped, with
the reason each was rejected or parked. Entries identify missing semantics,
unsupported matcher claims, noise, overlap or unfinished drafting. They are
recorded so the same ground is not re-mined.

## Coraza-history proposals (CRZ-05)

All 36 proposal texts were reviewed independently of harvested packets and
diffs. One literal-length advisory ships; these 35 proposals do not. A failed
draft is not evidence that the defect cannot be expressed syntactically.

### External contracts and noise

- `c-ifdef-on-enum-member` — overlaps `zstd-ifdef-on-enum-constant` for its
  known constant; arbitrary dependency names require declaration information.
  This is also the CRZ-03 duplicate, counted once.
- `c-foreign-allocator-libc-free` — allocation provenance and the required
  destructor are external library contracts.
- `c-optional-dlsym-called-unchecked` — optionality and loader guarantees
  cannot be established from the pointer call alone.
- `nginx-intervention-negative-return-unhandled` — the helper's negative
  sentinel and required response need its API contract.
- `c-size-t-to-int-ffi-unchecked` — callee parameter types and effective
  range constraints require semantic analysis.
- `c-inspection-body-submit-result-ignored` — the return convention and
  forwarding policy must establish whether ignoring the call is a defect.
- `c-dedup-freed-handle-erased-early` — aliasing and the deduplication helper's
  access to earlier slots are necessary to prove the lifecycle error.
- `go-close-channel-with-live-sender` — sender completion and cancellation
  guarantees are missing from the proposed syntax.
- `go-transfer-encoding-first-value-only` — completeness depends on the
  source API and consumer's protocol policy, not a generic index-zero access.
- `go-range-value-address-mutated` — addressing a range copy is valid;
  the helper's mutation and intended storage update must be established.
- `go-hijack-state-set-before-success` — wrapper state semantics and delegated
  error handling are needed to establish the harmful transition.
- `go-pooled-transaction-state-not-reset` — syntax does not define the full
  per-request reset set or ownership across pool reuse.
- `go-bounds-guard-uses-stale-cursor` — distinct spellings do not prove
  distinct cursor values or reachable out-of-bounds access.
- `nginx-read-file-short-read-accepted` — partial consumption may be intended;
  the proposal's positive itself calls `use(data, n)`.
- `go-transform-result-changed-always-true` — the Boolean's contract is local;
  a constant true result need not be wrong.
- `go-contains-for-startswith-predicate` — a helper name alone does not
  establish the intended matching semantics.
- `go-json-exported-response-field-without-tag` — default JSON field names
  can be the intended wire contract; proving drift requires a schema.

### Parked CRZ-04 drafts

- `go-writer-zero-nil-short-write` — four attempts failed from fixture YAML,
  method-pattern parsing or zero matches. A future method/signature matcher
  must distinguish an empty-input early return from an unconditional short
  write; the contract remains a useful candidate.
- `go-readfrom-iocopy-self-recursion` — the failed draft did not bind receiver
  and method. The proposal also overstates unconditional recursion: source
  [`WriterTo` dispatch precedes destination `ReaderFrom`](https://pkg.go.dev/io#Copy)
  when implemented by the source. A future advisory
  needs receiver binding and this limit.
- `go-html-entity-index-without-hash-length-guard` — no defensible draft was
  produced. Guard order, earlier bounds and the actual indexing branch need
  examination; a tightly bounded future shape remains possible.
- `go-decimal-parse-of-hex-entity` — the attempted call pattern produced zero
  matches from a parsing mismatch. `Atoi(digits)` alone also lacks evidence
  that `digits` is hexadecimal.
- `go-default-overwrites-configured-processor` — a force flag can intentionally
  override configuration; the proposed syntax lacks fallback semantics.
- `go-next-index-bound-gt-not-gte` — no draft was produced. An ordered guard
  and access may support a bounded advisory, but prior guards and control flow
  must not be inferred from disconnected descendants.
- `go-loop-format-assignment-overwrites` — per-iteration replacement can be
  correct; intended append semantics are not syntactic.
- `go-log-level-method-hardcodes-error` — method and constant names do not
  establish the logger's severity contract.
- `go-non-nil-slice-index-zero` — the syntax also admits maps and pointers;
  slice type and earlier length guarantees are not established.
- `go-index-plus-one-with-lte-bound` — no matcher was drafted. Same-condition
  syntax is a plausible future candidate, but type, prior bounds and a
  supported diagnostic remain unestablished.
- `go-parser-invalid-input-panic` — neither untrusted input nor the parser's
  error/recovery contract follows from a panic on a line value.
- `go-xml-token-prefix-slice-off-by-one` — `token[1:4] == "XML"` can correctly
  skip a leading delimiter; the expected token origin is missing.
- `go-time-layout-literal-20-seconds` — no draft was produced. The concrete
  date layout is a useful future advisory, but intentional literal text cannot
  be called a proven seconds defect from this proposal alone.

### Draft survivors rejected by claim defense

Each counterexample below produced one diagnostic with its draft using
`ast-grep scan --rule <draft.yml> --stdin --json`. All five rule, fixture and
snapshot sets were removed.

- `nginx-chain-aggregate-used-per-element` —
  `for (...) { seen |= cl->buf->last_buf; if (seen) break; }` matched.
  Stopping after observing a terminal flag does not misclassify later links;
  the branch is not constrained to current-link handling.
- `nginx-chain-terminal-flag-overwritten` —
  `for (...) { current = cl->buf->last_buf; use_current(current); }` matched.
  Per-link assignment is correct here; no aggregate state or later use is
  required by the matcher.
- `nginx-empty-ngx-str-converted-to-null` —
  `if (value.len == 0) { return ERROR; } else { *out = NULL; return ERROR; }`
  matched. Descendant search includes the opposite branch and establishes
  neither successful conversion nor an API prohibition on NULL for emptiness.
- `c-read-eof-breaks-before-requested-length` —
  `while (attempts > 0) { if (cancelled == 0) break; attempts--; }` matched.
  No read or remaining-byte update is required; legitimate termination becomes
  a claimed truncated read. Even a read loop may check completeness afterward.
- `go-range-outside-bounds-and` — `if x < 10 && y > 20 { return }` matched.
  The regex does not bind the compared value and calls this reachable condition
  unreachable. It also depends on whitespace and admits unrelated nested
  expressions. A future AST-bound advisory must state that bound ordering is
  assumed.

## c and nginx

- `nginx-str-data-passed-to-nginx-nul-wrappers` — extending
  `nginx-str-data-passed-to-libc` to `ngx_strcmp`, `ngx_strstr`, `ngx_strchr`,
  and `ngx_strcasecmp` produced 47 findings across the local nginx-module
  corpus, dominated by configuration-parser directive arguments. The nginx
  development guide explicitly says directive arguments are NUL-terminated,
  while syntax cannot distinguish them from request-derived strings. The
  existing libc-sink rule remains the narrower review signal.
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

## Snuffleupagus history harvest

- `c-stat-then-mkdir-toctou` — the exact paired-call shape is already shipped.
  `c-toctou-access-then-open` lists `stat`, `lstat` and `access` as the check
  and `mkdir` among its actions, and matches the same-variable pairing in one
  block. A probe over `if (stat(p, &st) != 0) { mkdir(p, 0700); }` and its
  brace-free variant produced one finding each from the existing rule, so a
  second rule would emit a duplicate diagnostic on identical code with no added
  precision. Broadening beyond the exact shape — to `access`, `open` or `creat`
  sinks — was the same ground the shipped rule already holds, and narrowing to
  `mkdir` alone adds nothing the shipped action list does not carry. Recorded
  here rather than shipped; the shipped rule's `stopBy: end` cross-function
  reach is a separate finding, filed in `issues.md`.

### Round 2 (deep pass)

- `c-deref-then-null-check` — from the null-deref fixes
  <https://github.com/jvoisin/snuffleupagus/commit/c25c8a1>,
  <https://github.com/jvoisin/snuffleupagus/commit/138e97b> and
  <https://github.com/jvoisin/snuffleupagus/commit/b3f5254>, each of which added
  a missing `!ptr` test to a guard that already dereferenced the pointer. The
  syntactic residue is "a pointer is used, and later tested for NULL", but the
  test that makes the use safe is routinely in the caller — all three upstream
  sites take the pointer from a `zend_execute_data` the engine is contracted to
  populate, so the pre-fix code was defensive-hardening, not a live crash.
  Reduced to one function the claim also inverts on the correct guard-first
  ordering. Probed with a matcher requiring, in one `compound_statement`, both a
  `field_expression` on `$P` and a `!$P` test, over a four-case control:
  `if (!p) return; use(p->f);` (correct), `use(p->f); if (!p) return;` (the
  defect), a test of a different pointer, and a deref into a local. It produced
  two findings — the defect *and* the correct guard-first case. ast-grep has no
  cross-relation binding and no statement ordering between two `has` clauses of
  the same node, so the matcher cannot separate "tested before use" from "tested
  after use"; the arm that would state the order is exactly the one the engine
  will not express here. Dropped: half the findings would be correct code, and
  the deciding fact — which callers can pass NULL — is reachability, not
  syntax.
- `c-strlen-on-binary-buffer` — from
  <https://github.com/jvoisin/snuffleupagus/commit/6d7adde>, which replaced
  `strlen(serialized_str)` with the known byte count because a serialized PHP
  object embeds NUL bytes. The defect is entirely about what the buffer
  *contains*; the call `strlen(x)` is correct on every NUL-terminated string and
  the matcher cannot read the difference. A narrower shape — `strlen` on a
  pointer that a `memcpy` in the same block filled with an explicit length — was
  probed over a two-case control holding the upstream defect and a correct
  `memcpy(b, src, strlen(src) + 1); strlen(b)` C-string copy. It produced two
  findings, one on each: the length available at the copy says nothing about
  whether the content is binary. Dropped as dataflow.
- `c-inet-ntop-size-not-dstlen` — from `sp_network_utils.c`, where `inet_ntop`
  is sized with the address-family constant rather than the destination's own
  capacity. Deciding that this is wrong requires the declared capacity of `dst`,
  which arrives as a parameter; the shipped `c-strncat-size-misuse` already
  holds the sub-case where the size argument is a `sizeof` of the destination.
  Dropped: no syntactic sub-claim survives the reduction.
- `c-zend-string-init-leak` — from the leak fixes
  <https://github.com/jvoisin/snuffleupagus/commit/996c461> and
  <https://github.com/jvoisin/snuffleupagus/commit/14c76b9>, which added a
  missing `zend_string_release`. The shape is "allocated in this block, not
  released in this block", the same co-occurrence heuristic the shipped
  `c-free-without-null` already carries with its documented weakness. A
  `zend_string` is routinely returned, stored in a config node, or handed to the
  engine, so absence of a local release is the normal case rather than the
  defect. Probed with "`zend_string_init` in a block with no
  `zend_string_release`" over a four-case control — the upstream leak, the fixed
  form, a function returning the string, and one storing it into a struct field.
  It produced three findings: the leak plus both correct ownership transfers.
  Duplicating an existing diagnostic's precision is a drop under the SNUF-02
  precedent.

### Round 3 (broad pass)

Sources swept: the shipped default ruleset `config/default.rules`, the
ecosystem rulesets `config/suhosin.rules`, `config/rips.rules`,
`config/detect_dangerous_extensions.rules`, and the CVE/exploit references those
rules cite. The retained rules are `php-putenv-loader-env`,
`php-ini-set-security-option` and `php-include-stream-wrapper`.

- `php-function-exists-recon` — from the "Detect some backdoors via environment
  recon" block of `config/default.rules`, which drops
  `function_exists("system")` and `is_callable("exec")` for the whole execution
  family. Snuffleupagus can afford this because it acts at request time on a
  hardened deployment where the block is a tripwire whose false positives cost a
  log line; a static rule reports the same shape on every capability probe in
  ordinary code. `function_exists('exec')` before choosing between `exec` and a
  library fallback is the standard portable spelling, and it is
  indistinguishable from a webshell's probe by syntax alone — the deciding fact
  is what the surrounding branch then does, which is dataflow. Probed over a
  four-case control holding a webshell probe, a portable capability check
  guarding a library fallback, a `function_exists` on an unrelated extension
  function, and an `is_callable` on a `$this` method: the shape produced two
  findings, the probe and the legitimate fallback. Dropped as an unfixable
  false-positive rate at any useful severity.
- `php-curl-setopt-sslengine` — from
  `sp.disable_function.function("curl_setopt").param("option").value("10089")`,
  added for <https://github.com/php/php-src/issues/22035>. The claim reduces to
  a single literal option constant on a single function, which the shipped
  `php-curl-ssl-verification-disabled` already reaches with the identical
  `curl_setopt` positional/named-argument scaffolding; adding a third constant
  to that rule's existing alternative would be the whole change. A separate rule
  emitting a second diagnostic on the same `curl_setopt` call with no added
  precision is a drop under the SNUF-02 precedent, and the option itself is a
  legitimate client-certificate engine selector, so it does not belong inside a
  rule whose message states that verification is off.
- `php-session-cookie-params-insecure` — from `sp.auto_cookie_secure` and the
  `sp.cookie.name("PHPSESSID").samesite("lax")` default. The shipped
  `php-insecure-cookie-flags` covers `setcookie`/`setrawcookie`, and
  `session_set_cookie_params` is genuinely uncovered, but the two call shapes
  differ in a way that defeats the same claim: `session_set_cookie_params`
  legitimately omits the flags because `session.cookie_secure` and
  `session.cookie_httponly` are set in php.ini, which is the *recommended*
  deployment. Absence of an argument therefore carries no information, and the
  only sub-claim that survives is an explicitly passed `false`, which is a
  one-line shape already better served by the ini audit. Probed over a
  three-case control — explicit `false`, omitted flags with php.ini expected to
  carry them, and the array form with `'secure' => true` — the omission arm
  reported the correct php.ini-configured deployment. Dropped: the informative
  half is the configuration file, not the call site.
- `php-rips-filename-scoped-patches` — the whole of `config/rips.rules` and the
  application-specific `spip`, `typo3` and `xenforo` rulesets. Every rule there
  is a virtual patch keyed on `filename_r(...)` plus a specific function in a
  specific released version of a specific application; the security claim is
  entirely "this file, in this product, at this version", carried by the
  `filename` predicate and not by any syntax the matcher would see. Reduced to
  the syntax alone, each becomes a match on an ordinary call such as `substr`,
  `define` or `save_module`. Dropped: these are deployment configuration for a
  runtime WAF, not a rule family, and the pack has no version-pinning
  vocabulary to express them.
- `php-mail-header-newline-literal` — from
  `sp.disable_function.function("mail").param("to").value_r("\\n")` in
  `config/suhosin.rules`. The value the rule inspects is the *runtime* argument,
  which is the injected header; a literal newline written into a constant `To:`
  argument in source is a typo, not an attack, and the request-derived case is
  already the shipped `php-mail-header-request`. Dropped: reading argument
  values at runtime is exactly the capability a syntactic matcher does not have,
  and this is the clearest instance of the round 1 lesson in the sweep.

## powershell

- `powershell-invoke-expression-constant-argument` — a rule for
  `Invoke-Expression` on a wholly constant argument (single-quoted verbatim
  string, or a double-quoted string with nothing to interpolate). Probed with a
  matcher that inverted the dynamic-input clause of
  `powershell-invoke-expression-dynamic-argument`: over
  `Invoke-Expression 'Get-Date'`, `Invoke-Expression "Get-ChildItem C:\"` and
  `iex 'Set-Location C:\temp'` it produced three findings, all on code whose
  executed text is fixed by the source and therefore carries no injection risk
  at all. The shape is a style defect — the interpreter is pointless — not a
  security one, and shipping it would put a security-pack finding on inert code
  while adding no precision to the two rules that report genuinely dynamic
  input. The distinction is instead documented in the dynamic-argument rule's
  own note, so a reader who hits that rule learns why the constant form is out
  of shape.
- `powershell-encodedcommand-invocation` — a rule for
  `powershell.exe -EncodedCommand <base64>`. Probed with a matcher over
  `command_parameter` values beginning `-Enc`: it matched
  `powershell.exe -EncodedCommand $b64` and `pwsh -enc $payload` as intended,
  but also `Get-Item -Encoding utf8 x`, because PowerShell resolves parameters
  by unambiguous prefix and `-Encoding` shares one with `-EncodedCommand`.
  Tightening the regex to the full `-EncodedCommand` spelling would then miss
  every abbreviated form (`-enc`, `-e`) that real droppers actually use, which
  is the entire population the rule exists to catch. Neither end of that
  trade-off is worth a rule; the shape also belongs to process-launch auditing
  of a host command line rather than to a PowerShell-source lens, since the
  encoded payload is opaque to this parser either way.
- `powershell-add-type-constant-variable-resolution` — an extension to
  `powershell-add-type-dynamic-source` that would suppress the finding when the
  variable in the source argument is provably assigned a literal earlier in the
  same scope. Probed by hand over the shapes a bounded same-scope proof would
  have to survive: `$code = 'public class X {}'` followed by a `foreach` body
  that reassigns `$code`; an assignment before a function call that could
  rebind the name through `Set-Variable -Scope 1`; and a dot-sourced file
  supplying the assignment. A syntax-only matcher sees none of the three, so
  every candidate proof was heuristic rather than sound, and each one
  suppresses a genuine finding whenever the rebinding sits outside its window.
  Suppression that is wrong in the unsafe direction is worse than no
  suppression at all for a security lens, so the extension is not shipped; the
  gap is documented in `limitations.md` instead.
- `powershell-foreach-object-dynamic-process` — the `-Process` half of the
  InjectionHunter dynamic-dispatch candidate, for `ForEach-Object -Process
  $body`. Rejected on the parameter's own binding contract: `-Process` is typed
  `[scriptblock]` and refuses a string outright — `@("a") | ForEach-Object
  -Process "Write-Output hi"` raises `ParameterBindingException`, and an
  explicit `[string]` cast fails the same way with "Cannot convert ... of type
  System.String". So a variable bound there already holds a compiled script
  block, and passing one is the idiomatic way to parameterise a pipeline
  (`function Invoke-Each { param([scriptblock]$Body) $items | ForEach-Object
  -Process $Body }`). The only way to reach `-Process` from text is
  `[scriptblock]::Create`, which `powershell-dynamic-scriptblock-api` already
  reports, so the rule would add no coverage and fire on correct code.
- `powershell-foreach-object-positional-member` — the same candidate's
  positional form, `$objs | ForEach-Object $v`. Rejected because the shape is
  type-dependent, not syntactic: verified on pwsh 7 that a *string* in that
  position binds to `-MemberName` and dispatches (`$v = "GetType"` prints
  `String`), while a *script block* in the identical position binds to
  `-Process` and runs as a pipeline body (`$v = { $_.ToUpper() }` prints `A`).
  The matcher cannot read which, so the rule would either miss the sink or
  report every parameterised pipeline. Only the explicitly named `-MemberName`
  form is unambiguous, and that ships as
  `powershell-foreach-object-dynamic-member`.
- `powershell-dynamic-member-access` — a rule for a non-constant property or
  method name, `$o.$prop` and `$o.$name($arg)`. The grammar does expose it
  cleanly: `member_name` holds the variable, so a matcher is easy to write.
  Probed over the shapes it would meet, and every one is the language's normal
  reflection idiom rather than a defect: `foreach ($k in $hash.Keys) { $obj.$k
  }`, `$row.$columnName`, `$config.$env:COMPUTERNAME`, `$props | ForEach-Object
  { $obj.$_ }`. The invocation half is no better — `$handlers[$k].$method()` and
  `foreach ($t in $tests) { $suite.$t() }` are a dispatch table and a test
  runner, which is precisely what the syntax exists for. Separating an
  attacker-chosen name from a table lookup needs the name's origin, which is
  dataflow. Naked dynamic access is also not an execution sink on its own:
  `$o.$prop` reads a property. The dispatch-sink residue — a cmdlet that
  *invokes* the named member — ships instead as
  `powershell-foreach-object-dynamic-member`.
- `powershell-hand-rolled-quote-escape` — a rule for hand-rolled escaping such
  as `$v -replace "'", "''"`, on the theory that
  `[System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent`
  is the correct API. Rejected twice over. First, the shape is not a defect:
  doubling `'` for a single-quoted PowerShell string is exactly what
  `EscapeSingleQuotedStringContent` does, so the hand-rolled form is *correct*,
  and a rule cannot claim otherwise without knowing the destination grammar.
  Second, `-replace` is one `comparison_expression` kind used for all string
  rewriting, and a probe could not separate the escaping intent from ordinary
  correct code — `$field -replace '"', '""'` (CSV quoting), `$name -replace
  "[^a-zA-Z0-9]", "_"` (slug sanitising) and `$p -replace '\\', '/'` (path
  normalising) are indistinguishable from it. The defect only exists once the
  result reaches an interpreter, and that sink is a separate statement joined by
  a variable. Verified redundant: scanning `Invoke-Expression ("Get-Item '" +
  ($p -replace "'","''") + "'")` and the two-statement `$cmd = ...` /
  `Invoke-Expression $cmd` form with the shipped pack already reports both
  through `powershell-invoke-expression-dynamic-argument`, so the escaping
  expression adds no finding the pack does not already make.
- `powershell-cmd-argument-passing` — a rule for `cmd /c dir $path`, where a
  variable follows the invoked program rather than being part of a quoted
  command string. Probed against the same corpus as
  `powershell-native-shell-dynamic-command`: the shape is ordinary argument
  passing, which is the remedy the shipped rule's message recommends, and
  reporting it would make the recommended fix itself a finding. The residual
  risk — the invoked program re-parsing its own argument — is a property of
  that program, not of the PowerShell source, and a PowerShell-source lens
  cannot distinguish `dir` from a wrapper that re-invokes a shell.
  The general shape has now been raised and refuted three times, twice by
  review of `powershell-native-shell-dynamic-command` (PR #14, rounds 1 and 2)
  and once again on the same grounds during the follow-up sweep. The premise is
  correct each time — cmd genuinely parses its whole remaining command line —
  but the conclusion does not follow, because the value only becomes live if
  the callee re-parses it, and for the overwhelmingly common callee it does
  not. Reporting the general shape would report the very remedy both native
  shell rules recommend.
  **A bounded subset of it did ship**, as
  `powershell-native-shell-nested-shell-argument`. The discriminator is the
  CALLEE, which is the one part of the residual risk a PowerShell-source lens
  can decide: when the program the execution switch invokes is itself `cmd`,
  `powershell` or `pwsh`, a trailing dynamic value demonstrably reaches a
  second shell parser, and that is knowable from the source alone. So
  `cmd /c cmd /c $x` and `cmd /c powershell -Command $x` are reported while
  `cmd /c dir $path` and `cmd /c git log $ref` remain out, and the callee
  anchor is immediate — `cmd /c wrapper.bat cmd /c $x` stays out, because what
  `wrapper.bat` does with its arguments is exactly the undecidable part. That
  bound is what separates the shipped rule from this rejected general shape;
  the rejection stands for everything outside it.
- `powershell-splatted-transport-bypass` — the splat half of the
  transport-verification candidate, intended to flag
  `$p = @{ SkipCertificateCheck = $true }` followed by
  `Invoke-WebRequest @p`. Rejected as unmatchable rather than undesirable.
  Splatting binds parameters exclusively through the `@variable` form, and the
  grammar confirms it: `New-PSSessionOption @opts` parses to a `command` whose
  only element is a `variable` node whose text is `@opts`, carrying no key
  names at all. The hashtable holding the unsafe key is a separate statement,
  and joining the two requires following an assignment through whatever
  reassignments, function boundaries and dot-sourced files sit between them —
  the same unsound same-scope proof already rejected for
  `powershell-add-type-constant-variable-resolution`. The inline form
  `Invoke-RestMethod @{ SkipCertificateCheck = $true }` *is* syntactically
  visible, but it is not a splat: `@{ ... }` in argument position is a
  hashtable *value* bound to a parameter (`-Body`, or positionally to `-Uri`),
  so PowerShell never reads `SkipCertificateCheck` as a parameter name there
  and a rule matching it would report a key that binds nothing. The packet's
  "splats only when the unsafe key is syntactically visible" condition is
  therefore never satisfiable for this shape, and no splat matcher ships.
- `powershell-invoke-webrequest-skip-header-validation` — the neighbouring
  `-SkipHeaderValidation` switch, considered while establishing the
  `-SkipCertificateCheck` prefix boundary. Rejected because it disables a
  client-side sanity check on header *formatting*, not a transport trust
  decision: it lets a caller send a header value the .NET client would
  otherwise refuse. That is a request-splitting concern whose severity depends
  entirely on whether the header value is attacker-influenced, which this lens
  cannot establish, and bundling it into a certificate-validation rule would
  put a transport-trust message on code that makes no trust decision.
  `-SkipHttpErrorCheck` was rejected on the same reading: it only stops the
  cmdlet throwing on a 4xx/5xx status.
- `powershell-pssession-option-no-compression` — the remaining
  `New-PSSessionOption -No*` switches, `-NoCompression` and
  `-NoMachineProfile`. Rejected as performance and profile settings that
  disable no verification; they are named here because they are the reason the
  shipped rule's `-NoEncryption` boundary starts at `-NoE`: the binder rejects
  `-No` as ambiguous between all three, verified by binding each prefix against
  the full Windows parameter set.

### PSScriptAnalyzer differential harvest

PSScriptAnalyzer 1.25.0 was installed and run against a probe corpus covering
the six candidate families, alongside the shipped pack, under PowerShell 7.6.5.
The differential is the reason these five are rejected: each family maps to a
PSScriptAnalyzer rule that fires on the real PowerShell AST, resolves command
aliases, and matches case-insensitively — three things a syntax-only matcher
either cannot do or can only approximate. Duplicating them would add findings
that are strictly worse than the ones consumers already get, so
**PSScriptAnalyzer is the preferred analyzer for all five**, and this pack
deliberately leaves them to it. Only the .NET type half of the broken-hash
family survived, as `powershell-broken-hash-algorithm-type`, because that is
the one shape PSScriptAnalyzer does not check at all.

- `powershell-allow-unencrypted-authentication` — duplicate of
  `PSAvoidUsingAllowUnencryptedAuthentication`. Probed over
  `Invoke-WebRequest -AllowUnencryptedAuthentication`, the lowercase spelling,
  `Invoke-RestMethod`, and the `iwr` alias: PSScriptAnalyzer reported all four,
  including the alias form, which it resolves to the real cmdlet name. A
  syntactic rule would have to enumerate alias spellings by hand and would
  still miss any alias a user defines locally.
- `powershell-convertto-securestring-plaintext` — duplicate of
  `PSAvoidUsingConvertToSecureStringWithPlainText` (severity Error). Probed over
  the named, positional, lowercase, and pipeline (`'p' | ConvertTo-SecureString
  -AsPlainText -Force`) forms: PSScriptAnalyzer reported every one, the pipeline
  form included. The pipeline shape is exactly the case a `command`-anchored
  matcher handles worst, since the string is not an argument of the call.
- `powershell-plaintext-password-parameter` — duplicate of
  `PSAvoidUsingPlainTextForPassword` and `PSAvoidUsingUsernameAndPasswordParams`
  (the latter Error). Probed over `param([string]$Password)`, a `$Passwd`
  variant, a correctly typed `[SecureString]$Secure`, and a username/password
  pair: PSScriptAnalyzer reported the unsafe ones, stayed silent on the
  `SecureString` parameter, and additionally flagged the credential-pair shape
  that a single-parameter matcher cannot see. Its claim rests on the parameter's
  declared type, which is precisely the fact syntax alone does not carry.
- `powershell-empty-catch-block` — duplicate of `PSAvoidUsingEmptyCatchBlock`.
  Probed over a bare `catch {}`, a typed `catch [System.Exception] {}`, and a
  catch containing only a comment: PSScriptAnalyzer reported all three,
  including the comment-only body, which it treats as empty because it reads
  statements rather than source text.
- `powershell-assignment-in-condition` — duplicate of
  `PSPossibleIncorrectUsageOfAssignmentOperator` and
  `PSPossibleIncorrectUsageOfRedirectionOperator`. Probed over `if ($x = 5)`,
  `while ($y = 1)`, `if ($a > $b)`, and the correct `if ($x -eq 1)`:
  PSScriptAnalyzer reported the three mistakes across both `if` and `while` and
  stayed silent on the comparison. It also distinguishes assignment from
  redirection, which share no syntax with each other and would need two separate
  rules here for no gain.

The one retained shape, recorded here so the boundary is not re-litigated:
`PSAvoidUsingBrokenHashAlgorithms` is scoped to the `-Algorithm` parameter of
`Get-FileHash`. Probed over nine spellings, it reported the three `Get-FileHash`
ones (`MD5`, lowercase `md5`, `SHA1`) and reported **nothing** for
`[System.Security.Cryptography.MD5]::Create()`,
`[System.Security.Cryptography.SHA1]::Create()`,
`[System.Security.Cryptography.MD5CryptoServiceProvider]::new()`,
`[System.Security.Cryptography.SHA1Managed]::new()`, or the `New-Object` form.
The shipped pack reported nothing for any of the nine. That is a demonstrated
consumer gap in the shape that matters most, since the .NET types are how MD5
and SHA-1 are reached for anything other than hashing a file on disk.
