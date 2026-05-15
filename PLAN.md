# CapitalOps Backend - Implementation Notes

## Recent Changes

### Cleanup (May 2026)
- `tmp_gui/` directory deleted from API repo (accidental GUI copy committed to backend repo)
- `__MACOSX/` and `~~/` artifacts removed from GUI repo tracking
- `.DS_Store` removed from tracking in both repos
- `.env` removed from tracking in GUI repo
- Backend PLAN.md updated with architecture notes confirming no fallback storage for new features

### Entitlement Polling Service (May 2026)

**Purpose:** Background job that monitors Accela and ArcGIS for permit/entitlement status changes and writes them to the DB.

**New Files:**
- `app/services/accela_client.py` - Accela API wrapper with OAuth2 token caching
- `app/services/arcgis_client.py` - ArcGIS FeatureServer query helper
- `app/services/entitlement_poller.py` - APScheduler job that polls and detects changes

**Data Sources:**
- Accela Civic Platform API (Hillsborough + Pinellas counties) — workflow status, inspections
- ArcGIS REST (Hillsborough + Pinellas) — hearing schedules

**Automated Behavior:**
- Status change → creates PermitEvent + notifies PM
- New hearing date → creates PermitEvent + notifies PM
- New inspections from Accela → creates PermitEvent + notifies PM

**Scheduler:** BackgroundScheduler runs every 30 min (configurable via `POLLER_INTERVAL_MINUTES`).

**Manual Trigger:** `POST /api/v1/entitlement/poll/trigger` (Sponsor Admin only)

**Env Vars Required:**
```
POLLER_INTERVAL_MINUTES=30
ACCELA_BASE_URL=https://apis.accela.com
ACCELA_CLIENT_ID=       # From developer.accela.com
ACCELA_CLIENT_SECRET=   # From developer.accela.com
ACCELA_HILLSBOROUGH_AGENCY=hillsboroughcountyfl
ACCELA_PINELLAS_AGENCY=pinellascountyfl
HILLSBOROUGH_ARCGIS_HEARINGS_URL=   # ArcGIS FeatureServer URL
PINELLAS_ARCGIS_HEARINGS_URL=       # ArcGIS FeatureServer URL
ARCGIS_PARCEL_FIELD=PARCEL_NUM
```

### Entitlements & Notifications (May 2026)

**Purpose:** Track permits/entitlements for projects with event history, and notify users of changes.

**New Files:**
- `app/models.py` - Added `EntitlementRecord`, `PermitEvent`, `FieldMedia`, `Notification` models
- `app/routes/entitlement.py` - CRUD endpoints for entitlements and notifications
- `app/notifications.py` - Utility function `create_notification()` for DB-write layer
- `migrations/versions/add_entitlements_and_notifications.py` - Migration for 4 new tables

**Routes Added:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/entitlement/` | List records (filterable by `project_id`, `status`) |
| GET | `/api/v1/entitlement/:id` | Single record with events |
| POST | `/api/v1/entitlement/` | Create record |
| PATCH | `/api/v1/entitlement/:id` | Update (auto-creates PermitEvent on status change) |
| POST | `/api/v1/entitlement/:id/events` | Add event |
| GET | `/api/v1/entitlement/notifications` | Unread notifications for current user |
| PATCH | `/api/v1/entitlement/notifications/:id/read` | Mark notification read |

**Notification Triggers:**
- Entitlement status change → PM gets notification
- Work order vendor change → vendor's user gets notification

### Field Media Upload (May 2026)

**Purpose:** Upload photos/videos for projects and work orders via S3 presigned URLs.

**New Files:**
- `app/routes/vendor.py` (updated) - Added media upload endpoints:
  - `POST /api/v1/vendor/media/presign` - Get presigned S3 PUT URL
  - `POST /api/v1/vendor/media` - Create FieldMedia record
  - `GET /api/v1/vendor/media` - List media (with presigned GET URLs)
  - `DELETE /api/v1/vendor/media/:id` - Delete media record + S3 object

**S3 Key Pattern:** `field-media/{project_id or work_order_id}/{uuid4}/{filename}`

### AES-256-GCM Column-Level Encryption (May 2026)

**Purpose:** Encrypt sensitive PII and financial data at rest.

**New Files:**
- `app/utils/encryption.py` - Encryption helpers and TypeDecorator
- `app/routes/dev.py` - Dev utilities including seed endpoint

**New Encrypted Columns on Investor Model:**
- `tax_id`, `date_of_birth`, `phone`, `bank_account_number`, `routing_number`

### Financial Reports (May 2026)

**Purpose:** Allow Sponsor Admins to generate and share financial summaries for projects or deals.

**New Files:**
- `app/routes/reports.py` - Financial report endpoints
- `migrations/versions/add_financial_reports.py` - FinancialReport table migration

**Model:** `FinancialReport` with fields: id, created_by_user_id, recipient_user_id, project_id (nullable), deal_id (nullable), report_type, title, content (JSON), is_read, created_at. Check constraint ensures project_id or deal_id is set.

**Routes Added:**
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/reports/` | Generate and share a report (sponsor_admin only) |
| GET | `/api/v1/reports/` | List reports received by current user |
| GET | `/api/v1/reports/sent` | List reports sent by current user |
| GET | `/api/v1/reports/:id` | Get single report (marks as read) |

**User Picker Endpoint:**
- `GET /api/v1/auth/users` - Returns all platform users (id, full_name, email, role) for report recipient selection (sponsor_admin only)

### Track Record (May 2026)

**Purpose:** Portfolio-style summary of all projects a user has been involved with as PM.

**New Endpoint:**
- `GET /api/v1/execution/track-record/:user_id` - Returns aggregated summary with per-project breakdown. Access: sponsor_admin (any user), project_manager (own record only).

**Response:** user info, summary stats (total/completed/active projects, budget managed, on-time completion rate, avg milestone completion %, risk flag counts, entitlement count), and project array with milestone/risk/entitlement counts.

---

## Setup Instructions

### 1. Generate Encryption Key

Run this command **in the backend directory**:

```bash
python -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Copy the output - this is your `FIELD_ENCRYPTION_KEY`.

### 2. Set Environment Variable in Railway

1. Go to Railway project dashboard
2. Navigate to your backend service → Variables
3. Add: `FIELD_ENCRYPTION_KEY` = `<generated key from step 1>`

### 3. Database Migration for New Tables

Run this SQL in your PostgreSQL database:

```sql
-- Entitlements
CREATE TABLE entitlement_records (
    id SERIAL PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
    parcel_number VARCHAR(100) NOT NULL, agency VARCHAR(200) NOT NULL,
    application_number VARCHAR(100), entitlement_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL, submitted_date DATE NOT NULL,
    hearing_date DATE, approved_date DATE, notes TEXT, source_url VARCHAR(500),
    created_at TIMESTAMP, updated_at TIMESTAMP
);

CREATE TABLE permit_events (
    id SERIAL PRIMARY KEY, entitlement_record_id INTEGER NOT NULL REFERENCES entitlement_records(id),
    event_type VARCHAR(50) NOT NULL, previous_value VARCHAR(200), new_value VARCHAR(200),
    detected_at TIMESTAMP NOT NULL, source VARCHAR(20) NOT NULL, created_at TIMESTAMP
);

-- Field Media
CREATE TABLE field_media (
    id SERIAL PRIMARY KEY, project_id INTEGER REFERENCES projects(id),
    work_order_id INTEGER REFERENCES work_orders(id),
    uploaded_by_user_id INTEGER NOT NULL REFERENCES users(id),
    media_type VARCHAR(20) NOT NULL, s3_key VARCHAR(500) NOT NULL,
    s3_bucket VARCHAR(200) NOT NULL, filename VARCHAR(300) NOT NULL,
    caption VARCHAR(500), uploaded_at TIMESTAMP NOT NULL, created_at TIMESTAMP,
    CONSTRAINT check_field_media_project_or_work_order CHECK (project_id IS NOT NULL OR work_order_id IS NOT NULL)
);

-- Notifications
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
    notification_type VARCHAR(50) NOT NULL, title VARCHAR(200) NOT NULL,
    body TEXT NOT NULL, related_entity_type VARCHAR(50), related_entity_id INTEGER,
    is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP
);

-- Encrypted Investor columns
ALTER TABLE investors ADD COLUMN tax_id TEXT;
ALTER TABLE investors ADD COLUMN date_of_birth TEXT;
ALTER TABLE investors ADD COLUMN phone TEXT;
ALTER TABLE investors ADD COLUMN bank_account_number TEXT;
ALTER TABLE investors ADD COLUMN routing_number TEXT;
```

### 4. AWS S3 Configuration

Set these env vars in Railway:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION` (e.g., `us-east-1`)
- `AWS_BUCKET_NAME`

---

## Dev Seed Endpoint

To re-seed demo data, call this endpoint (requires admin login):

```javascript
fetch('https://capialops-backend-api-production.up.railway.app/api/v1/dev/seed', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('auth_token') }
}).then(r => r.json()).then(console.log)
```

Credentials: `admin` / `admin123`

---

## Architecture Notes

### Repo Split
- **capitalOps-API** (Flask/SQLAlchemy/PostgreSQL): All backend features. All new features (entitlements, field media, notifications, poller, encryption) live here only.
- **capitalOps-GUI** (React/Vite): Frontend. The `server/` directory contains an Express dev proxy to Flask API (in-memory storage is NOT used for new features — only as fallback for older routes if Flask is unreachable).
- **No fallback storage for new features**: Entitlements, field media, and notifications exist only in the Flask API and have no in-memory fallback.

---

## Known Issues Resolved

- Railway build failures due to `mise`/`uv` version issues
- Demo data seeding fails if encrypted columns missing from database
- Admin user missing from Railway DB (restored via dev seed endpoint)
- JSX structure errors in work-orders.tsx (fixed)
- Presigned URL generation for S3 uploads