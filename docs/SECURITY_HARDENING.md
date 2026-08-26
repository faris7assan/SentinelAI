# Security Hardening Checklist

The following items are required before treating the authentication service as production-ready.

## 1. JWT Secret — fail closed

Current code falls back to a fixed placeholder when `JWT_SECRET_KEY` is absent. Production behavior should fail during startup instead.

Recommended pattern:

```python
JWT_SECRET = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET_KEY is required")
```

Generate the value outside source control and inject it through deployment-time secret management.

## 2. CORS — restrict trusted origins

Do not use `allow_origins=["*"]` together with credentialed requests in a production authentication service. Configure an explicit allow-list such as the deployed frontend origin(s).

## 3. Account Provisioning — explicit authorization

The registration endpoint should not be publicly usable for arbitrary role creation. Require an authenticated administrator or move initial-user provisioning into a controlled bootstrap process.

## 4. Secret Rotation

If a JWT secret, OAuth credential, database password, API key, or cloud credential is ever committed, rotate it immediately. Removing the value from the latest commit is not sufficient if the secret existed in repository history.

## 5. Production Verification

Before deployment, verify:

- JWT secret is supplied and unique per environment.
- CORS contains only trusted origins.
- Registration/admin endpoints enforce authorization.
- OAuth client secrets are deployment-time secrets.
- Database and Redis credentials are not committed.
- Automated security checks pass.
