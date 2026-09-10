# nginx rule classification

nginx is a rule domain, not a separate ast-grep parser language. nginx source
and modules are parsed as C, so all rules below stay under `rules/c` with
`language: c`. The `nginx-*` namespace is retained only where the claim depends
on an nginx API, data model, lifecycle, ABI, or source policy. A syntactically
generic matcher can still be nginx-specific when its diagnostic is valid only
inside nginx code.

Audit performed 2026-09-10 over every nginx-prefixed rule:

| Rule | Classification | Dependency |
| --- | --- | --- |
| `nginx-buf-flush-before-last-buf` | nginx | `ngx_buf_t` flag semantics |
| `nginx-conf-return-code-confusion` | nginx | nginx callback return contracts |
| `nginx-cpp-line-comment` | nginx | nginx source policy; `//` is valid C |
| `nginx-finalize-plus-return-rc` | nginx | request finalization lifecycle |
| `nginx-init-returns-http-status` | nginx | nginx hook and status conventions |
| `nginx-plain-inline` | nginx | nginx portability policy; `inline` is valid C |
| `nginx-pool-cleanup-add-size-discarded` | nginx | pool cleanup API ownership |
| `c-string-sizeof-includes-nul` | C | only C string-literal and `sizeof` semantics |
| `nginx-string-sizeof-includes-nul` | compatibility | disabled alias for explicit old-ID promotion |
| `nginx-strlen-on-ngx-str-data` | nginx | `ngx_str_t` length convention |
| `nginx-strstrn-length-off-by-one` | nginx | nginx substring API contract |
| `nginx-atoi-unchecked` | nginx | nginx conversion API error contract |
| `nginx-command-offset-struct-mismatch` | nginx | directive-table ABI |
| `nginx-escape-uri-alloc-without-double` | nginx | `ngx_escape_uri` sizing contract |
| `nginx-format-libc-length-modifier` | nginx | nginx formatter dialect |
| `nginx-headers-out-push-next` | nginx | response-header list ABI |
| `nginx-intervention-poll-error-page` | nginx | nginx error-page re-entry lifecycle |
| `nginx-raw-heap-alloc` | nginx | nginx allocator ownership policy |
| `nginx-raw-malloc` | nginx | nginx pool-vs-system-heap policy |
| `nginx-send-header-return-ignored` | nginx | header-filter return contract |
| `nginx-send-header-two-valued` | nginx | header/output-filter return contract |
| `nginx-shm-data-write-without-lock` | nginx | shared-zone locking model |
| `nginx-shm-exists-reload-test` | nginx | shared-memory reload lifecycle |
| `nginx-slab-alloc-unzeroed` | nginx | nginx slab allocation contract |
| `nginx-slab-locked-without-lock` | nginx | nginx slab locking contract |
| `nginx-str-data-passed-to-libc` | nginx | `ngx_str_t` termination convention |
| `nginx-table-missing-sentinel` | nginx | nginx static-table ABI |
| `nginx-thread-pool-get-null-name` | nginx | nginx thread-pool API contract |
| `nginx-unchecked-array-push` | nginx | nginx array/list allocation contract |
| `nginx-unchecked-module-ctx` | nginx | nginx request-context lifecycle |
| `nginx-unchecked-palloc` | nginx | nginx pool allocation contract |
| `nginx-use-after-finalize` | nginx | nginx request lifetime |

The former `nginx-string-sizeof-includes-nul` was renamed because its matcher
deliberately includes non-nginx structures and its claim requires no nginx
contract. The nginx development guide remains useful evidence for the original
case, but evidence provenance does not determine rule language. Consumers must
apply the [rule ID migration](id-migrations.md) when updating the pack.
