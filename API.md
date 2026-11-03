# Route access matrix

| Route | Method | Allowed caller | Enforcement |
|---|---|---|---|
| `/login` | GET/POST | Anonymous | Password hash; CSRF |
| `/logout` | GET | Authenticated | Audit event |
| `/` | GET | Authenticated | SQL scoped to owned/granted docs |
| `/upload` | GET/POST | Owner | Role check; file allowlist/size/signature |
| `/docs/<id>` | GET | Owner or read/edit grantee | Object-level read check |
| `/docs/<id>` | POST | Owner or edit grantee | Object-level edit check |
| `/docs/<id>/download` | GET | Owner or read/edit grantee | Fresh permission check before send |
| `/docs/<id>/grant` | POST | Owner of document | Role + ownership check |
| `/docs/<id>/revoke` | POST | Owner of document | Role + ownership check |
| `/docs/<id>/delete` | POST | Owner of document | Role + ownership check |
| `/admin` | GET | Admin | Admin role check; audit metadata only |

Unauthorised document IDs return 404. Role violations return 403. State-changing form routes require a CSRF token.
