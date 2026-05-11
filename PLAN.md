# CapitalOps Backend - Implementation Notes

## Recent Changes

### AES-256-GCM Column-Level Encryption (May 2026)

**Purpose:** Encrypt sensitive PII and financial data at rest using AES-256-GCM authenticated encryption.

**New Files:**
- `app/utils/encryption.py` - Encryption helpers and TypeDecorator
- `app/routes/dev.py` - Dev utilities including seed endpoint
- `migrations/versions/add_encrypted_investor_fields.py` - Alembic migration

**Modified Files:**
- `app/models.py` - Added encrypted columns to Investor model
- `app/__init__.py` - CORS headers, seed_demo_data() with force parameter
- `requirements.txt` - Added `cryptography>=44.0.0`, `flask-migrate>=4.0.5`
- `pyproject.toml` - Added same dependencies
- `alembic.ini` - Alembic configuration

**New Encrypted Columns on Investor Model:**
- `tax_id` - SSN or EIN
- `date_of_birth` - Date of birth
- `phone` - Contact phone number
- `bank_account_number` - Bank account for distributions
- `routing_number` - Bank routing number

### Setup Instructions

#### 1. Generate Encryption Key

Run this command **in the backend directory**:

```bash
python -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Copy the output - this is your `FIELD_ENCRYPTION_KEY`.

#### 2. Set Environment Variable in Railway

1. Go to Railway project dashboard
2. Navigate to your backend service → Variables
3. Add: `FIELD_ENCRYPTION_KEY` = `<generated key from step 1>`

#### 3. Database Migration (if not using Flask-Migrate)

Run this SQL in your PostgreSQL database to add the encrypted columns:

```sql
ALTER TABLE investors ADD COLUMN tax_id TEXT;
ALTER TABLE investors ADD COLUMN date_of_birth TEXT;
ALTER TABLE investors ADD COLUMN phone TEXT;
ALTER TABLE investors ADD COLUMN bank_account_number TEXT;
ALTER TABLE investors ADD COLUMN routing_number TEXT;
```

### Dev Seed Endpoint

To re-seed demo data, call this endpoint (requires admin login):

```javascript
fetch('https://capialops-backend-api-production.up.railway.app/api/v1/dev/seed', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('auth_token') }
}).then(r => r.json()).then(console.log)
```

Credentials: `admin` / `admin123`

### Known Issues Resolved

- Railway build failures due to `mise`/`uv` version issues (unrelated to encryption)
- Demo data seeding fails if encrypted columns missing from database
- Admin user missing from Railway DB (restored via dev seed endpoint)