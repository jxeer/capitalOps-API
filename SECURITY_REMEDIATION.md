# Security Remediation — Credential Rotation Required

The following credentials are currently hardcoded in the CapitalOps codebase or stored in environment configuration. **All must be rotated immediately** if this is a production deployment, as the current values may be compromised or exposed through git history, logs, or accidental commits.

---

## Immediate Action Required

Rotate all credentials below via the respective service's IAM/console, then update Railway environment variables. Do not commit new credentials to git.

---

## Credentials Requiring Rotation

### AWS (S3 Field Media Upload)

| Variable | Location | Risk |
|----------|----------|------|
| `AWS_ACCESS_KEY_ID` | `app/routes/vendor.py`, `app/routes/compat.py` | Exposed in git history |
| `AWS_SECRET_ACCESS_KEY` | `app/routes/vendor.py`, `app/routes/compat.py` | Exposed in git history |
| `AWS_REGION` | `app/routes/vendor.py`, `app/routes/compat.py` | Low — region only |
| `AWS_BUCKET_NAME` | `app/routes/vendor.py`, `app/routes/compat.py` | Exposed in git history |

**How to rotate:** AWS IAM Console → Users → Security Credentials → Create new access key.

### Google OAuth

| Variable | Location | Risk |
|----------|----------|------|
| `GOOGLE_OAUTH_CLIENT_ID` | `app/routes/google_auth.py` | Exposed in git history |
| `GOOGLE_OAUTH_CLIENT_SECRET` | `app/routes/google_auth.py` | Exposed in git history |

**How to rotate:** Google Cloud Console → APIs & Services → Credentials → OAuth 2.0 Client IDs → Regenerate.

### Accela API (Entitlement Poller)

| Variable | Location | Risk |
|----------|----------|------|
| `ACCELA_CLIENT_ID` | `app/services/accela_client.py` | Exposed in git history |
| `ACCELA_CLIENT_SECRET` | `app/services/accela_client.py` | Exposed in git history |
| `ACCELA_BASE_URL` | `app/services/accela_client.py` | Low — URL only |

**How to rotate:** developer.accela.com → Application → Regenerate client secret.

### Railway Deployment

| Variable | Location | Risk |
|----------|----------|------|
| `RAILWAY_PUBLIC_DOMAIN` | `app/routes/google_auth.py` | Low — deployment URL |

**Note:** Railway auto-generates a new public domain on redeploy. A new domain can be obtained by triggering a new deployment.

### JWT / App Secret

| Variable | Location | Risk |
|----------|----------|------|
| `JWT_SECRET_KEY` | `app/__init__.py` | Default dev value committed to git — must be set to strong random value in production |
| `SECRET_KEY` | `app/__init__.py` | Same as above — acts as fallback for JWT_SECRET_KEY |

**How to fix:** Set `JWT_SECRET_KEY` to a strong random value in Railway environment variables:
```bash
python -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

### Email (Resend) — Password Reset Only

| Variable | Location | Risk |
|----------|----------|------|
| `RESEND_API_KEY` | `app/routes/auth.py` | Exposed in git history |

**How to rotate:** Resend Dashboard → API Keys → Regenerate.

---

## Already Cleaned Up

The following were removed in this audit session:

- `backend/.gitignore` — Added `.env`, `.env.*`, `supporting-files/`, `instance/`, `app/uploads/*.jpg`
- `backend/app/uploads/*.jpg` — Test images removed from git
- `backend/app/__init__.py` — Added production startup guard that refuses to start if `JWT_SECRET_KEY` uses the default dev value
- `backend/main.py` — `debug=True` replaced with `debug = os.environ.get("FLASK_ENV") == "development"`

---

## No Action Needed (Not Sensitive)

The following environment variables are public or non-sensitive:

- `FLASK_ENV` — environment indicator (`development`, `production`, `testing`)
- `FRONTEND_ORIGIN` — public URLs for CORS
- `DATABASE_URL` — Railway-managed PostgreSQL connection (rotate via Railway)
- `AWS_REGION` — AWS region identifier
- `AWS_BUCKET_NAME` — public bucket name (not an access credential)
- `ACCELA_BASE_URL` — public API endpoint URL
- `ACCELA_HILLSBOROUGH_AGENCY`, `ACCELA_PINELLAS_AGENCY` — county identifiers
- `ARCGIS_PARCEL_FIELD` — field name identifier
- `HILLSBOROUGH_ARCGIS_HEARINGS_URL`, `PINELLAS_ARCGIS_HEARINGS_URL` — public ArcGIS URLs
- `POLLER_INTERVAL_MINUTES`, `JWT_ACCESS_TOKEN_EXPIRES_MINUTES`, `JWT_COOKIE_NAME` — app config
- `DISABLE_SEED` — deployment flag
- `ENVIRONMENT` — environment indicator
- `FIELD_ENCRYPTION_KEY` — must be rotated if encryption keys need refresh (affects DB data)