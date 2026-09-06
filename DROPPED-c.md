# Dropped C / nginx candidates

- `c-mktemp-tmpnam` — already shipped as `c-insecure-temp-name`, which matches the
  same four API names with the same call-name matcher.
- `c-signed-length-compare` — the claim depends on the declared type of the compared
  variable, which the matcher cannot read from a parameter list without also matching
  every unsigned comparison; no precise syntactic sub-claim survives the reduction.
- `nginx-escape-uri-two-pass-mismatch` — the real defect pairs a sizing call in a
  length handler with a copy call in a separate copy handler, so the two calls are
  never in one syntactic scope; the same-function reduction only restates the
  shipped `nginx-escape-uri-alloc-without-double`.
- `nginx-regex-captures-unnamed-before-alloc` — requires knowing which regex last
  populated `r->captures`, which is cross-function state.
- `nginx-pnalloc-buffer-uninitialized-len` — needs the byte count actually written,
  a dataflow fact; `b->last = b->end` alone is correct whenever the buffer was filled.
- `nginx-cpymem-unbounded` — the claim is that the copied length exceeds the
  destination capacity, which is arithmetic reasoning, not syntax.
- `nginx-subrequest-ctx-on-r-not-main` — most filters legitimately operate per
  subrequest; the absence of an `r != r->main` test is not a defect.
- `nginx-ctx-stores-buf-from-in-chain` — whether the saved buffer outlives the call
  depends on the buffer's ownership flags, which syntax cannot read.
- `nginx-main-count-increment-without-done` — the balancing decrement is routinely in
  a callback in another function, so the co-occurrence check is not a claim.
- `nginx-finalize-after-send-header-fallthrough` — subsumed by the shipped
  `nginx-finalize-plus-return-rc`, which states the precise sibling-statement shape.
- `nginx-http-status-from-variable-getter` — the `not_found` half is a co-occurrence
  heuristic and the status half is already covered by the shipped
  `nginx-conf-return-code-confusion` family.
- `nginx-pfree-non-large` — depends on the pool's `max`, a runtime value.
- `nginx-atoi-result-used-as-length` — needs the declared type of the receiving
  variable to distinguish the defect from correct signed handling.
- `nginx-header-value-len-zero-deref` — the guard may be any earlier length test in
  the function or in the caller; absence of a local comparison is not a defect.
- `c-double-free-cleanup-no-null` — a single-owner destructor that frees a field
  without nulling it is correct; the claim needs reachability, not syntax.
- `c-callback-frees-owner-then-uses` — reduced and shipped as the precise
  `nginx-use-after-finalize`; the generic multi-destructor form has no such shape.
- `nginx-conf-string-injected-into-protocol` — requires knowing whether the value was
  validated earlier, which is dataflow across the parser.
