# Sources for Go rules

Rule id -> evidence consulted during the harvest.

- go-template-html-cast — https://pkg.go.dev/html/template (typed strings);
  CVE-2026-27142, CVE-2026-39823, CVE-2026-56858 html/template escaper bugs
  (golang/go#78913); https://www.sourcery.ai/vulnerabilities/go-template-html-vulnerable
- go-template-parse-dynamic — https://onsecurity.io/article/go-ssti-method-research/ ;
  https://gusralph.info/go-ssti-research/ ; https://github.com/github/securitylab/issues/812
- go-text-template-response — https://www.oligo.security/blog/safe-by-default-or-vulnerable-by-design-golang-server-side-template-injection
- go-file-open-request-path — CVE-2026-35471 (goshs traversal, file deletion);
  GO-2026-4585 (FileBrowser share traversal); GO-2026-4502 (echo Static
  backslash); CVE-2026-25766; https://pkg.go.dev/net/http#ServeFile caveat
- go-path-check-string-match — GO-2026-4502 echo backslash traversal on Windows;
  CVE-2026-35471; https://pkg.go.dev/path/filepath#IsLocal
- go-http-server-no-header-timeout — gosec G112/G114;
  https://github.com/securego/gosec/issues/823 ;
  https://github.com/cert-manager/cert-manager/pull/6534
- go-request-body-unbounded — CVE-2026-54448 (Trivy); CVE-2026-73232 (ffuf);
  https://pkg.go.dev/net/http#MaxBytesReader
- go-decompress-readall — CVE-2026-54448; CVE-2026-32282 (archive/tar sparse map);
  https://www.vulncheck.com/advisories/rpcx-denial-of-service-via-gzip-decompression-bomb-in-wire-protocol
- go-exec-shell-c — CVE-2026-29042 (nuclio, github.com/nuclio/nuclio/pull/4030);
  https://snyk.io/blog/understanding-go-command-injection-vulnerabilities/
- go-http-request-url-ssrf — CVE-2026-27018 (Gotenberg scheme bypass);
  CVE-2026-33205 (Gin SSRF); CVE-2025-47912, CVE-2026-25679 (net/url host parsing)
- go-http-redirect-request-value — CVE-2026-52802 (Gogs redirect_to);
  CVE-2022-25295 (gophish backslash bypass);
  https://www.stackhawk.com/blog/golang-open-redirect-guide-examples-and-prevention/
- go-mac-compare-variable-time — CVE-2024-30257 (1panel);
  https://pkg.go.dev/crypto/hmac#Equal ;
  https://www.slingacademy.com/article/avoiding-timing-attacks-with-constant-time-comparisons-in-go/
- go-aes-gcm-static-nonce — CVE-2026-26014 (Pion DTLS nonce reuse);
  https://pkg.go.dev/crypto/cipher#AEAD
- go-rsa-generatekey-small — gosec G403; crypto/rsa Go 1.24 minimum-size release note
- go-cipher-mode-weak — gosec G405/G501; Go 1.24 deprecation of CFB/OFB
  (https://pkg.go.dev/crypto/cipher)
- go-jwt-unverified — CVE-2026-22817, CVE-2026-27804, CVE-2026-23552 (algorithm
  confusion); CVE-2025-30204 (ParseUnverified allocation DoS);
  https://pkg.go.dev/github.com/golang-jwt/jwt/v5#UnsafeAllowNoneSignatureType
- go-cookie-insecure-flags — CVE-2025-34291 (Langflow SameSite/CORS chain);
  OWASP Session Management Cheat Sheet
- go-cors-wildcard-credentials — https://pentesterlab.com/blog/golang-cors-vulnerabilities ;
  CVE-2025-34291; CVE-2026-30924 (qui);
  https://github.com/gofiber/fiber/security/advisories/GHSA-fmg4-x8pw-hjhg
- go-file-perm-world-writable — gosec G302/G306;
  https://github.com/securego/gosec/issues/1126 (ModePerm); CWE-276
- go-tempfile-fixed-path — gosec G303; CWE-377
- go-strconv-atoi-narrow-cast — gosec G109/G115;
  https://docs.boostsecurity.io/rules/gosec-109.html
- go-unsafe-pointer-uintptr-arith — https://pkg.go.dev/unsafe#Pointer (rule 3);
  go vet unsafeptr
- go-xml-decoder-strict-off — https://pkg.go.dev/encoding/xml#Decoder (Strict, Entity)
- go-gob-decode-network — https://pkg.go.dev/encoding/gob (security note:
  not designed to be hardened against adversarial inputs)
