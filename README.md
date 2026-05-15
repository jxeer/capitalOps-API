# CapitalOps

**Capital + Governance Operating Layer for Real Estate Development**

CapitalOps is a full-stack application that handles investor alignment, deal distribution, governance interpretation, vendor/maintenance visibility, and structured reporting for real estate development portfolios.

Both the API backend and the React frontend run in a single Repl.

---

## Quick Start

### 1. Environment Variables

The following environment variables must be set before booting. In Replit, add them via the Secrets panel.

#### Required

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (provided automatically by Replit's PostgreSQL add-on) |

#### Optional (API)

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET_KEY` | dev fallback key | Secret used to sign JWT access tokens. **Required in production — set a strong random value.** Falls back to `SECRET_KEY` env var if `JWT_SECRET_KEY` is not set. |
| `JWT_ACCESS_TOKEN_EXPIRES_MINUTES` | `60` | Access token lifetime in minutes |
| `FRONTEND_ORIGIN` | `http://localhost:5173,http://localhost:3000` | Comma-separated origins allowed by CORS. Set to your deployed frontend URL in production. |
| `FLASK_ENV` | _(unset)_ | Set to `development` to enable auto-seeding of demo data on startup. Set to `production` to block auto-seeding even if Replit env vars are present. |

#### Optional (Frontend)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `/api/v1` | Base URL for all API calls from the frontend. In this Repl, Vite proxies `/api` to the Flask backend, so the default works out of the box. If deploying the frontend separately, set this to the full API URL (e.g., `https://your-api.replit.app/api/v1`). |

### 2. Boot the App

The Repl runs two workflows automatically:

| Workflow | Command | Port | Purpose |
|---|---|---|---|
| **Start application** | `npx vite --config client/vite.config.ts` | 5000 | React frontend (webview) |
| **API Server** | `python main.py` | 3001 | Flask JSON API |

Vite proxies all `/api` requests from the frontend to the Flask backend on port 3001. No extra configuration needed.

Both workflows start automatically when the Repl boots. The webview shows the frontend on port 5000.

### 3. Log In

Once both workflows are running, open the webview. You'll see the login page.

| Role | Username | Password |
|---|---|---|
| Sponsor Admin | `admin` | `admin123` |
| Project Manager | `pm` | `pm123` |
| General Contractor | `gc` | `gc123` |

Log in with any account to see the project dashboard.

### 4. Seed Demo Data

Demo data (users, projects, deals, milestones, vendors) is seeded automatically on startup in development environments (`FLASK_ENV=development` or Replit dev workspace).

To seed manually:
```bash
FLASK_APP=main.py flask seed
```

Seeding is idempotent — it skips if users already exist. It never runs when `FLASK_ENV=production`.

### 5. Database Migrations

All schema changes are managed through Alembic migrations in `migrations/versions/`.
Never use inline `ALTER TABLE` statements — all new columns and tables must be added via migration files.

**Run migrations on first deploy and after each deploy that includes new migration files:**
```bash
flask db upgrade
```

Railway runs `flask db upgrade` automatically as a release command before the server starts (see `railway.toml`).

**Create a new migration:**
```bash
flask db migrate -m "Descriptive message"
# Then edit the generated file in migrations/versions/
```

**Manually apply all pending migrations:**
```bash
flask db upgrade
```

**Roll back the last migration:**
```bash
flask db downgrade
```

---

## Architecture

```
Browser
  │
  ▼
┌──────────────────────────────────┐
│  capitalops-web (port 5000)      │
│  React + TypeScript + Vite       │
│  All API calls → VITE_API_BASE_URL│
└──────────┬───────────────────────┘
           │  Vite proxy: /api → localhost:3001
           ▼
┌──────────────────────────────────┐
│  capitalops-api (port 3001)      │
│  Flask JSON API                  │
│  PostgreSQL + SQLAlchemy         │
│  JWT Auth (flask-jwt-extended)   │
└──────────┬───────────────────────┘
           │  (future)
           ▼
┌──────────────────────────────────┐
│  Coral8 Execution Backbone       │
│  (not yet wired)                 │
└──────────────────────────────────┘
```

**Architectural rule:** The React frontend only calls the CapitalOps API. The API is the gateway that will later call Coral8. The frontend never calls Coral8 directly.

---

## API Endpoints (v1)

All routes are under `/api/v1/`. All routes except login require a JWT:

```
Authorization: Bearer <access_token>
```

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | Authenticate, returns `{ accessToken, user }` |
| GET | `/api/v1/auth/me` | Current user profile |

### Dashboard
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/dashboard/` | Portfolio overview stats |

### Module 1: Capital Engine
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/capital/` | Capital overview (stats + lists) |
| GET | `/api/v1/capital/deals` | Deal pipeline |
| GET | `/api/v1/capital/deals/:id` | Deal detail + allocations |
| GET | `/api/v1/capital/investors` | Investor listing |
| POST | `/api/v1/capital/investors` | Create investor (admin only) |
| POST | `/api/v1/capital/allocations` | Create allocation (admin only) |
| GET | `/api/v1/capital/matching` | Deal-investor matching engine |

### Module 2: Execution Control
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/execution/` | All projects with metrics |
| GET | `/api/v1/execution/projects/:id` | Project detail + milestones |
| PATCH | `/api/v1/execution/milestones/:id` | Update milestone |
| GET | `/api/v1/execution/governance` | Governance event log |

### Module 3: Asset & Vendor Control
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/vendor/` | Vendor overview + stats |
| POST | `/api/v1/vendor/` | Register vendor (admin only) |
| GET | `/api/v1/vendor/work-orders` | Work order listing |
| POST | `/api/v1/vendor/work-orders` | Create work order |
| PATCH | `/api/v1/vendor/work-orders/:id` | Update work order |

---

## Role-Based Access Control

Permissions are enforced via JWT role claims (no extra DB lookup):

| Role | Access |
|---|---|
| **Sponsor Admin** | Full access to all three modules |
| **Project Manager** | Execution module only |
| **General Contractor** | Confirm milestones, limited vendor access |
| **Vendor** | Own work orders only |
| **Investor Tier 1** | View matched deals, submit allocations |
| **Investor Tier 2** | Priority access, enhanced reporting |

---

## Project Structure

```
main.py                          Flask API entry point (port 3001)
app/
  __init__.py                    App factory, JWT, CORS, DB init, seed data
  models.py                     SQLAlchemy models (11 entities)
  auth_utils.py                 get_current_user(), role_required()
  routes/
    auth.py                     Login + current user
    dashboard.py                Portfolio overview
    capital.py                  Module 1: Capital Engine
    execution.py                Module 2: Execution Control
    vendor.py                   Module 3: Asset & Vendor Control
client/
  vite.config.ts                Vite dev server (port 5000, proxy → 3001)
  index.html                    HTML entry point
  .env                          VITE_API_BASE_URL=/api/v1
  src/
    main.tsx                    React entry point
    App.tsx                     Router (/login, /dashboard)
    lib/api.ts                  API client (token storage, auth header)
    components/ProtectedRoute.tsx  Redirects to /login if no token
    pages/LoginPage.tsx         Login form
    pages/DashboardPage.tsx     Project table with metrics
```

---

## Tech Stack

### Backend
- Python 3.11 / Flask
- SQLAlchemy + PostgreSQL
- flask-jwt-extended (stateless JWT auth)
- Flask-CORS
- Werkzeug (password hashing)

### Frontend
- React 18 + TypeScript
- Vite
- React Router
