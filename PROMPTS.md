# PROMPTS.md — AI usage and development record

This document records AI assistance used during TrustVault development. Entries should reflect actual interactions, independently verified results, and real code changes.

## Reusable project context

- Server-side authorization is required on every document route.
- Document access must be checked against current permissions.
- Permission revocation must apply to the next request.
- AI suggestions must never grant document access automatically.
- Security limitations must be documented honestly.

## Entry 1 — Authorization and IDOR

- **Date:** 02/11/2026
- **Prompt summary:** Asked AI to review document authorization and identify ways a user could access another user's document by changing its ID.
- **AI assistance:** Reviewed server-side document access checks and cross-user isolation.
- **Issue or assumption checked:** Whether direct document URLs could bypass permission checks.
- **Independent verification:** Tested access using different user roles and direct document URLs.
- **Result:** Unauthorized document access was blocked and returned a Not Found response.
- **Commit:**(https://github.com/A-Hari-Narayana0805/trustvault/commit/8550298)

## Entry 2 — Permission revocation

- **Date:** 03/11/2026
- **Prompt summary:** Asked AI to help verify that revoked document permissions immediately prevent further access.
- **AI assistance:** Reviewed permission checks for document viewing and downloading.
- **Issue or assumption checked:** Whether a previously authorized viewer could continue accessing a document after revocation.
- **Independent verification:** Granted viewer access, tested access, revoked permission, and tested again.
- **Result:** The viewer could no longer access the document after revocation.
- **Commit:** (https://github.com/A-Hari-Narayana0805/trustvault/commit/8550298)

## Entry 3 — Audit integrity

- **Date:** 03/11/2026
- **Prompt summary:** Asked AI to review the HMAC-linked audit event implementation and its security limitations.
- **AI assistance:** Reviewed the audit event structure and the use of a separate HMAC secret.
- **Issue or assumption checked:** Whether HMAC chaining makes audit records impossible to tamper with.
- **Independent verification:** Inspected the audit implementation and its database writes.
- **Result:** Documented that compromise of both the database and HMAC key can defeat the protection.
- **Commit:** (https://github.com/A-Hari-Narayana0805/trustvault/commit/8550298)

## Entry 4 — Upload validation

- **Date:** 04/11/2026
- **Prompt summary:** Asked AI to review document upload validation and potential malicious file risks.
- **AI assistance:** Reviewed file extension restrictions, upload size limits, safe filenames, and file signature checks.
- **Issue or assumption checked:** Whether extension and basic signature validation provide complete malware protection.
- **Independent verification:** Inspected the upload validation implementation.
- **Result:** Documented the remaining limitation that the application does not provide comprehensive malware scanning.
- **Commit:** (https://github.com/A-Hari-Narayana0805/trustvault/commit/8550298)
## Entry 5 — Automated security testing and deployment

- **Date:** 04/11/2026
- **Prompt summary:** Asked AI to help diagnose failing security tests and verify the deployed application.
- **AI assistance:** Helped investigate a CSRF token initialization issue in the test helper.
- **Issue or assumption checked:** Tests initially failed because the login page had not been requested before reading the CSRF token from the session.
- **Independent verification:** Updated the test helper to request the login page first and ran pytest again.
- **Result:** Three automated security tests passed.
- **Commit:** (https://github.com/A-Hari-Narayana0805/trustvault/commit/8550298)

## AI usage limitations

AI suggestions were treated as assistance, not proof of security. Code, permissions, audit behavior, tests, and deployment configuration were checked independently. Any remaining limitations are documented in THREATS.md.
