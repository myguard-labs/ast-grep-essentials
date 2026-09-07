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
