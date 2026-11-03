# TrustVault

A security-first Flask MVP for the Snovasys RISE challenge.

## Run locally
Python 3.10+:
```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000.

## Demo accounts
| Role | Username | Password |
|---|---|---|
| Admin | admin | Admin-Demo-2026! |
| Owner | owner | Owner-Demo-2026! |
| Viewer | viewer | Viewer-Demo-2026! |

Replace demo credentials before public deployment.

## Security design
- Admin sees activity metadata; admin is not implicitly allowed to read documents.
- Owner uploads, edits metadata, grants/revokes read or edit access, and soft-deletes own documents.
- Viewer can read/download only explicitly granted documents.
- Each object route checks the current user and current grant in SQLite. Unauthorised IDs return 404.
- Files are outside static/public paths; download checks permission before sending bytes.
- Revocation is effective on the next request because no signed/public download links are created.
- Audit events use an HMAC-linked chain. Keep `AUDIT_HMAC_KEY` outside the DB. This is tamper-evident against DB-only modification, not against an attacker who controls both DB and key.

## Environment variables
Set strong independent random values for `FLASK_SECRET_KEY` and `AUDIT_HMAC_KEY`. Also configure persistent `DATABASE_PATH` and `FILE_STORAGE_PATH`. Upload limit defaults to 15 MiB.

## Deploy
Push to a public GitHub repo, create a Render Web Service, build `pip install -r requirements.txt`, start `gunicorn -w 1 -b 0.0.0.0:$PORT app:app`. Attach persistent disk and point both DB and file storage paths to it. Configure secrets in Render, deploy, then rotate demo passwords before sharing. This step requires your hosting/GitHub account access. Do not run with ephemeral storage.

## Honest limitations before real confidential use
No MFA, password reset, email verification, rate limiting, malware scanning, file content disarm, immutable WORM audit storage, external audit anchoring, file versions, retention/recovery UI, or production PostgreSQL. DOCX/XLSX are extension-validated but not malware-scanned. Add secure cookies behind HTTPS, CSP/security headers, monitoring, backups, and failed/denied-attempt logging. This is a challenge MVP, not a certified enterprise platform.
