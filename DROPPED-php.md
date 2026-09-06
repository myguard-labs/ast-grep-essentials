# Dropped PHP/WordPress candidates

- wp-delete-file-from-attached-meta (#11): needs the `get_post_meta(..., '_wp_attached_file')` result to flow through a variable into the delete sink; syntax cannot link the two statements.
- wp-esc-sql-unquoted (#8): deciding whether an escaped value lands inside SQL quotes requires reasoning about the concatenated string built across operands and variables, not a single syntactic shape.
- wp-wpdb-like-without-esc-like (#9): the injection arm restates php-sql-string-interp; the remaining `%s` arm needs the bound value's provenance, which is dataflow.
- wp-nonce-localized-publicly (#17): the enclosing enqueue hook name is only visible when the callback is an inline closure, so the claim is not syntactic in the common (named-callback) case.
- wp-sanitize-text-field-as-path-guard (#22): the sanitizer and the filesystem sink are almost always separate statements joined by a variable; the direct-wrapper form alone is too narrow to be worth a rule.
- php-eval-call (#24): already covered — php-exec-sink's function regex includes `eval`.
- php-assert-non-literal (#27): already covered — php-exec-sink's function regex includes `assert`.
- php-http-host-in-mail (#32): the poisoned link is built in one statement and mailed in another; linking them needs dataflow.
- php-unserialize-allowed-classes-true (#38): redundant — php-unserialize fires on every `unserialize` call regardless of the options argument.
- php-uniqid-as-token (#31): `uniqid` is already in php-weak-crypto's function regex, so every call site is reported there already.
- php-strip-tags-as-xss-guard (#37): redundant — php-echo-superglobal-xss does not list `strip_tags` as an encoder, so it already reports `echo strip_tags($_GET[...])`; verified by scanning that fixture with the existing rule.
