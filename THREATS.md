# Threat register — starter; expand with actual attack evidence

| Threat | MVP mitigation | Remaining gap / test to add |
|---|---|---|
| IDOR by changing document ID | Server-side `access()` on detail/download/edit routes; 404 for inaccessible objects | Add cross-user tests for every new route |
| Hidden-button bypass | Backend role and object checks; UI is not security | Remove each check locally and prove tests fail |
| Stale link after revocation | No public/signed URL; grants queried per request | Downloaded copies cannot be recalled |
| Viewer privilege escalation | Role decorators on upload/grant/revoke/delete/admin | Test all role/route combinations |
| Storage path guessing | Random opaque filenames; storage outside static directory | Host and backups must be protected |
| Malicious upload | Extension allowlist, size cap, safe filename, basic PDF/image signatures | No malware scan or archive-bomb defence |
| Audit tampering | HMAC-linked events with separate secret | DB+key compromise defeats this; add WORM/external anchoring |
| Missing audit evidence | Successful login/upload/download/change/grant/revoke/delete events recorded | Denied attempts and failed logins not yet logged |
| CSRF | Session-bound token on state-changing forms | Add automated CSRF regression tests |
| Session compromise | Werkzeug password hashing | Add secure-cookie config, expiry, MFA and rate limits |
| SQL injection | Parameterised SQL queries | Review every future query |
| Search leakage | Results SQL-scoped to owned/granted docs | Add search/export regression tests |
| Admin misuse | Admin activity metadata only, no implicit file read | Add alerting and privileged-action controls |
| Data loss | Soft delete; file remains stored | No recovery UI, backup/retention automation |

## Invariants
1. Every document operation authenticates and checks current permission on the server.
2. Grants are per document and named active user.
3. Revocation denies the next request.
4. Never place document bytes in a public/static directory.
5. Never claim HMAC audit is immutable against an attacker holding both database and key.
