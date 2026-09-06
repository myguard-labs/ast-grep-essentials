# Dropped Go candidates

Candidates from the harvest that were not shipped, with the reason each was
rejected. Every entry needs information the syntax tree does not carry.

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
