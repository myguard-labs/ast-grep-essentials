# Limitations — javascript, java, lua, bash harvest

One bullet per shipped rule, in the style of `docs/limitations.md`. Every rule
here is a syntactic matcher over a single file: it sees shapes, not types, taint
or reachability.

## javascript

- `js-child-process-shell-interpolation` sees a template literal or a `+`
  concatenation in the command slot of an `exec` family call. It cannot tell
  whether the interpolated value was validated upstream, and it does not read
  the `shell` option, so a `spawn` with an argv array and a concatenated
  executable path still matches while a shell-enabled call built from a variable
  does not.
- `js-dom-html-sink` recognises `DOMPurify.sanitize`, `sanitizeHtml` and
  `escapeHtml` by name only. A sanitizer under any other name, or one applied on
  an earlier line, reads as an unsafe value; a locally defined function called
  `sanitize` reads as safe.
- `js-express-open-redirect` requires the `req.*` access to be a direct argument
  of `res.redirect`. A value copied into a local variable, or checked against an
  allowlist before the call, is invisible, and so is a redirect helper wrapping
  the call.
- `js-express-reflected-response` matches only a template or a concatenation in
  the first argument. It cannot see a `Content-Type` set earlier that would make
  the body inert, and it does not recognise escaping wrappers, so an escaped
  concatenation still matches.
- `js-tls-verification-disabled` matches only literal `false`, the literal
  string `"0"` and an empty `checkServerIdentity`. A verification flag driven by
  an environment lookup or a configuration value is missed in both directions.
- `js-weak-hash-algorithm` cannot distinguish a security digest from a cache key
  or an ETag, which is the dominant benign use of MD5; it is a warning for that
  reason. An algorithm name held in a variable is not matched.
- `js-weak-cipher-algorithm` reads the algorithm string literally. It does not
  check IV uniqueness or key length, and a transformation assembled from
  configuration is missed.
- `js-jwt-algorithm-unpinned` looks only at the call site, so an options object
  built in a variable is reported as unpinned even when it pins the algorithm.
  `jwt.decode`, which never verifies, is deliberately out of scope.
- `js-cors-credentials-wildcard` does not follow an `origin` callback function,
  which can be safe or unsafe, and it does not correlate the two manual header
  calls with one another; each is judged on its own shape.
- `js-express-static-dotfiles` does not look at what the served directory
  contains, so a purpose-built directory of dotfiles matches.
- `js-vm-sandbox-dynamic-source` excludes a literal source even though the `vm`
  module is not an isolation boundary for literals either. It cannot show that
  the dynamic string is attacker-controlled.
- `js-insecure-random-secret` is a name heuristic. A security value under a
  neutral name is missed; a cosmetic identifier containing `key` or `session` is
  reported.

## java

- `java-weak-hash-algorithm` matches string literals only. A constant or a
  configured algorithm name is missed, and MD5 used as a checksum is a known
  false positive, which is why it is a warning.
- `java-weak-cipher-transformation` lists block ciphers explicitly on the ECB
  arm, because `ECB` in an RSA transformation is a naming artefact. It cannot
  see key length or IV reuse.
- `java-native-deserialization-sink` is a call-site matcher: an
  `ObjectInputFilter` installed on a separate statement, or a `Yaml` built with a
  `SafeConstructor` and stored in a variable, is not visible, so a filtered
  stream still matches.
- `java-sql-concat-query` requires at least one non-literal operand in the
  concatenation. A query assembled into a local variable first, and a bare
  identifier argument, are both invisible.
- `java-jndi-lookup-dynamic` treats any non-literal name as dynamic, so a name
  read from a configuration constant is reported. That false positive is
  accepted because a reachable dynamic lookup is severe.
- `java-expression-eval-dynamic` does not model a restricted SpEL evaluation
  context, so a `SimpleEvaluationContext`-guarded parse matches. The receiver is
  recognised by variable name for the parser and engine cases.
- `java-trust-all-tls` treats a body containing any statement as non-empty, so a
  stub that only logs is missed. A trust-all stub confined to a test profile
  still matches.
- `java-response-open-redirect` needs the request read in the argument itself.
  An allowlist check on an earlier line, or a value carried through a local
  variable, is invisible.
- `java-cookie-missing-flags` matches an inline `Cookie` construction only; a
  cookie configured through a variable and then added is missed. On the
  `ResponseCookie` arm a chain that sets one of the two flags is left alone, so a
  chain missing only `secure` is not reported. Container-level cookie
  configuration is invisible.
- `java-xml-factory-doctype-unset` scopes the hardening search to the enclosing
  method. A factory hardened in a helper, in a field initialiser, or by a
  secure-processing wrapper is a false positive, which is why it is a warning.
- `java-spring-csrf-disabled` cannot see whether the same chain sets a stateless
  session policy, which makes disabling CSRF defensible, so a token-only API is a
  known false positive.
- `java-format-string-not-literal` does not distinguish the locale-first
  `Formatter` overloads, so a call passing a `Locale` first is reported, and a
  constant format string held in a field is reported as non-literal.

## lua

- `lua-sql-string-concat` recognises `ngx.quote_sql_str` and `tonumber` by name
  only; a local function with either name reads as safe. A statement built into a
  variable on an earlier line is not matched.
- `lua-redirect-user-target` does not report an escaped value used as the whole
  location, even though `ngx.escape_uri` only protects a value placed in a query
  slot.
- `lua-response-reflect-unescaped` excludes `ngx.var.upstream_http_*` because
  those originate upstream, and it cannot see a content type set earlier that
  would make the body inert.
- `lua-subrequest-user-uri` inspects the first, URI argument only. The `args`
  option table is deliberately not inspected because the module escapes it, and
  `capture_multi` is not covered because its URIs sit in a nested table.
- `lua-http-client-verify-disabled` matches a literal `false` only; a verify flag
  passed through a variable or a configuration lookup is missed.
- `lua-io-open-user-path` requires an `ngx` request token in the path, which
  excludes the Kong plugin loader idiom but also misses a request value carried
  through a local variable. A traversal check on an earlier line is invisible.
- `lua-regex-user-pattern` does not check the fourth argument of `string.find`,
  so a plain find with `true` is reported even though it does no pattern
  matching.
- `lua-uri-args-unbounded` matches a literal zero only. A no-argument call is
  deliberately not matched because the module applies a default of 100, and a
  limit passed in a variable is missed; the matcher does not check that the
  `truncated` error is handled.
- `lua-insecure-random-token` is a name heuristic on the assignment target. A
  security value under a neutral name is missed; a cosmetic identifier containing
  one of the listed words is reported. The `os.tmpname` arm is precise.
- `lua-cjson-decode-unprotected` cannot see whether `cjson` was required as
  `cjson.safe` at the top of the file, because the call site looks identical, so
  a file using the safe module is a false positive. An enclosing `pcall` several
  frames up is also not seen.
- `lua-exit-without-return` reports a bare terminating call even as the last
  statement of a handler, where it behaves like a return in most phases. Which
  phase the code runs in is not visible.

## bash

- `sh-world-writable-permissions` reads the mode as a literal token, so a mode
  passed in a variable is missed, and a wide mode on a private per-user directory
  is still reported.
- `sh-secret-on-command-line` decides that a value is a secret from the variable
  name. A secret under a neutral name is missed, and a non-secret variable whose
  name happens to contain `KEY` is reported.
- `sh-predictable-temp-path` matches literal `/tmp` and `/var/tmp` paths and the
  dry-run `mktemp`. A path built from a `TMPDIR` expansion is not matched, and
  whether the directory is really shared is not checked.
- `sh-rm-rf-unguarded-variable` cannot see a `set -u` at the top of the file or a
  guard written as a separate test, so a script that already checks the variable
  is reported.
- `sh-container-isolation-disabled` matches literal flags and their separate
  values. Options composed in a variable are missed, and a lab script that
  legitimately needs a privileged container matches.
- `sh-host-hardening-disabled` reads literal tokens, so the same action performed
  through a variable or a configuration management tool is missed; a deliberate
  temporary change in an interactive script still matches.
- `sh-archive-extract-to-system-root` cannot see where the archive came from, so
  a vendor tarball extracted into the root matches. Extraction into any other
  directory is not reported, even though a malicious archive can escape it.
- `sh-path-search-includes-cwd` does not follow a PATH assembled in another
  variable and assigned later, and it does not judge whether the listed
  directories are themselves writable.
- `sh-remote-shell-string-interpolation` excludes the argv-after-double-dash form
  for `ssh` and excludes a single-word interpolating operand such as the host. It
  cannot tell whether the interpolated value is attacker-controlled, and a value
  already quoted for the remote shell still matches.
- `sh-process-substitution-shell-input` covers process substitution and here
  strings, which `sh-curl-pipe-shell` does not reach because no pipeline is
  involved. Vendor install instructions use this shape.
- `sh-printf-format-not-literal` reports a format string held in a variable on
  purpose, for example a reusable table row layout.
- `sh-arithmetic-context-injection` cannot see a `case` or regex guard applied on
  an earlier line, so a script that already validates the value is reported.
  Arithmetic on a variable from a non-positional source is not matched.
