# Dropped candidates — javascript, java, lua, bash harvest

One line of reason each. "Needs dataflow" means the claim cannot be reduced to a
precise syntactic sub-claim without either unbounded false positives or a
matcher that asserts more than syntax can show.

## javascript

- `js-path-join-request` — the `startsWith` containment guard is a separate
  statement, so the rule would flag every correctly guarded `path.join`; needs
  dataflow.
- `js-buffer-constructor-or-proto-key` (merge half) — a prototype-pollution guard
  lives inside the callee, invisible at the call site; needs dataflow. The
  `new Buffer(x)` half is a deprecation, not a defect the matcher can establish.
- `js-nosql-query-from-body` — distinguishing an operator-injectable whole-object
  argument from a scalar property requires type information about the request
  value; needs dataflow.
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
- `java-android-webview-unsafe` — the risky combination is `setJavaScriptEnabled`
  together with `addJavascriptInterface` across a class, and the individual
  settings are version-gated by `minSdk`, which is not in the file.
- `java-response-reflect` (XSS half of the composite candidate) — an escaping
  wrapper is recognisable only by name and the writer receiver is unconstrained,
  so the arm would fire on ordinary text output; the redirect half shipped as
  `java-response-open-redirect`.

## lua

- `lua-dynamic-load-string` — `load`, `loadstring` and `dofile` are already
  covered by the existing `lua-execution-sink`; the residual `setfenv` and
  `debug.*` surface is a sandbox-construction idiom, not a defect on its own.
- `lua-shared-dict-check-then-set` — proving a check-then-set race needs the same
  key expression in two statements plus the absence of a lock anywhere in the
  request path; needs dataflow.
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
- `sh-download-then-execute` (chmod-then-run half) — correlating `curl -o X` with
  a later `chmod +x X` and an execution of `X` needs a multi-statement window
  with metavariable reuse across commands; the process-substitution and
  here-string forms shipped as `sh-process-substitution-shell-input`, and the
  archive forms as `sh-archive-extract-to-system-root`.
