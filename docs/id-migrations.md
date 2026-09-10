# Rule ID migrations

Rule IDs are consumer-facing contracts. Update suppressions, severity overrides,
`--error` lists, reports, and allowlists when moving to a revision containing a
mapping below. Validate each promoted ID with a known positive after updating;
ast-grep can exit successfully when an `--error` ID is unknown.

| Date | Former ID | Replacement ID | Reason |
| --- | --- | --- | --- |
| 2026-09-10 | `nginx-string-sizeof-includes-nul` | `c-string-sizeof-includes-nul` | The rule has no nginx dependency and applies unchanged to ordinary C. |

The former ID remains as a `severity: off` compatibility alias. Normal scans
emit only the replacement ID, while an existing
`--error=nginx-string-sizeof-includes-nul` promotion activates the alias and
continues to fail on a known positive. That explicit promotion emits both the
legacy error and the replacement warning for each site; count-based reports
must account for the temporary duplicate. Scans that explicitly pass
`--include-off` also activate the alias and produce both IDs. Suppressions,
filters, reports, and other ID-based configuration still need the mapping
above.
