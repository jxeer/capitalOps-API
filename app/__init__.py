"""
CapitalOps API - Application Factory & Initialization

Pure JSON API backend for the CapitalOps operating layer.
No server-rendered templates — designed to be consumed by the
capitalops-web React frontend via Authorization: Bearer <JWT>.

This module defines the Flask application factory (create_app), which:
  1. Configures the app (JWT secret, database URI, SQLAlchemy options)
  2. Initializes extensions (SQLAlchemy, JWTManager, Flask-CORS)
  3. Registers all API route blueprints under /api/v1/
  4. Creates database tables and seeds demo data in development

Blueprint architecture:
  - auth_bp:      /api/v1/auth      — JWT authentication (login, me)
  - dashboard_bp: /api/v1/dashboard  — Portfolio overview aggregations
  - capital_bp:   /api/v1/capital    — Module 1: Capital Engine
  - execution_bp: /api/v1/execution  — Module 2: Execution Control
  - vendor_bp:    /api/v1/vendor     — Module 3: Asset & Vendor Control

Extensions are declared at module level so they can be imported
by other modules (e.g., `from app import db`).
"""

import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from datetime import timedelta
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS

# --- Extension Instances (module-level for shared access) ---

# SQLAlchemy ORM instance — manages all database models and sessions
db = SQLAlchemy()

# JWTManager instance — handles JWT creation, validation, and error responses
jwt = JWTManager()


def create_app():
    """
    Application factory function.

    Creates and configures the Flask app, initializes extensions,
    registers blueprints, and sets up the database.

    Returns:
        Flask: The fully configured Flask application instance.
    """
    app = Flask(__name__)

    # --- App Configuration ---

    # JWT signing key. In production, set JWT_SECRET_KEY env var to a strong random value.
    # Falls back to SECRET_KEY for compatibility, then to a dev-only default.
    app.config["JWT_SECRET_KEY"] = os.environ.get(
        "JWT_SECRET_KEY",
        os.environ.get("SECRET_KEY", "capitalops-dev-jwt-secret-change-in-production")
    )

    # Access token expiration — 1 hour by default, configurable via env var (in minutes)
    access_token_minutes = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", "60"))
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=access_token_minutes)

    # Token location — accept JWTs from BOTH Authorization header AND httpOnly cookies
    # This allows clients to use cookie-based auth for XSS protection while maintaining
    # Bearer token compatibility for API clients and the compat layer.
    app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
    app.config["JWT_HEADER_NAME"] = "Authorization"
    app.config["JWT_HEADER_TYPE"] = "Bearer"

    # Cookie configuration for httpOnly JWT storage (XSS protection)
    # These are used when the backend issues tokens via set_access_cookies()
    cookie_name = os.environ.get("JWT_COOKIE_NAME", "capitalops_token")
    app.config["JWT_ACCESS_COOKIE_NAME"] = cookie_name
    app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
    app.config["JWT_ACCESS_COOKIE_HTTP_ONLY"] = True
    app.config["JWT_ACCESS_COOKIE_SECURE"] = os.environ.get("ENVIRONMENT", "development") == "production"
    app.config["JWT_ACCESS_COOKIE_SAME_SITE"] = "Lax"

    # PostgreSQL connection string - uses Railway PostgreSQL if DATABASE_URL is set
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///capitalops.db"

    # Disable modification tracking to save memory (we don't use this feature)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Connection pool settings to handle database reconnections gracefully
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,   # Recycle connections every 5 minutes
        "pool_pre_ping": True, # Test connections before use to avoid stale connections
    }

    # --- Initialize Extensions ---

    db.init_app(app)
    jwt.init_app(app)

    # Enable CORS for the capitalops-web React frontend.
    # FRONTEND_ORIGIN controls which origin(s) are allowed.
    # In dev: defaults to localhost:5173 (Vite) and localhost:3000 (CRA).
    # In production: set FRONTEND_ORIGIN to the deployed capitalops-web URL.
    frontend_origin = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173,http://localhost:3000")
    allowed_origins = [o.strip() for o in frontend_origin.split(",") if o.strip()]

    CORS(app, resources={r"/api/.*": {
        "origins": allowed_origins,
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-Key"],
        "supports_credentials": True,
    }})

    # --- JWT Error Handlers ---
    # Return consistent JSON error responses for all JWT-related failures

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        """Return 401 when the access token has expired."""
        return jsonify({"error": "Token has expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error_string):
        """Return 401 when the token is malformed or invalid."""
        return jsonify({"error": "Invalid token"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error_string):
        """Return 401 when no Authorization header is provided."""
        return jsonify({"error": "Missing authorization header"}), 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        """Return 401 when the token has been revoked."""
        return jsonify({"error": "Token has been revoked"}), 401

    # --- Global HTTP Error Handlers ---
    # Ensure all error responses are JSON (never HTML) for API consumers

    @app.errorhandler(403)
    def forbidden_handler(error):
        """Return 403 JSON when access is denied (role/permission failure)."""
        return jsonify({"error": "Forbidden"}), 403

    @app.errorhandler(404)
    def not_found_handler(error):
        """Return 404 JSON when a resource or route is not found."""
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed_handler(error):
        """Return 405 JSON when the HTTP method is not allowed on a route."""
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error_handler(error):
        """Return 500 JSON on unhandled server errors."""
        return jsonify({"error": "Internal server error"}), 500

    # --- Health Check ---
    # Returns 200 on GET / for deployment health checks and uptime monitors.

    @app.route("/")
    def health_check():
        """Health check endpoint for deployment probes."""
        return jsonify({"status": "ok", "service": "capitalops-api"}), 200

    # --- Register Blueprints ---
    # All routes are versioned under /api/v1/ and return JSON only.

    from app.routes.auth import auth_bp
    from app.routes.google_auth import google_auth_bp
    from app.routes.uploads import uploads_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.capital import capital_bp
    from app.routes.execution import execution_bp
    from app.routes.vendor import vendor_bp
    from app.routes.compat import compat_bp
    from app.routes.dev import dev_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(google_auth_bp, url_prefix="/api/v1/auth/google")
    # Image upload — stores avatars as base64 data URLs in the DB (no S3 needed)
    app.register_blueprint(uploads_bp, url_prefix="/api/v1/upload")
    app.register_blueprint(dashboard_bp, url_prefix="/api/v1/dashboard")
    app.register_blueprint(capital_bp, url_prefix="/api/v1/capital")
    app.register_blueprint(execution_bp, url_prefix="/api/v1/execution")
    app.register_blueprint(vendor_bp, url_prefix="/api/v1/vendor")
    app.register_blueprint(dev_bp, url_prefix="/api/v1/dev")

    # GUI compatibility layer — serves flat REST endpoints at /api/ matching
    # the response format expected by the frontend GUI's Express proxy.
    # No JWT required (server-to-server calls from the GUI's Express server).
    app.register_blueprint(compat_bp, url_prefix="/api")
    
    # Serve static files from uploads directory for uploaded images
    from flask import send_from_directory
    uploads_dir = os.path.join(app.root_path, "uploads")
    
    @app.route("/uploads/<path:filename>")
    def serve_upload(filename):
        """Serve uploaded image files from the uploads directory."""
        return send_from_directory(uploads_dir, filename)

    # --- Database Initialization ---
    with app.app_context():
        # Create all tables defined by SQLAlchemy models (safe to call repeatedly)
        db.create_all()

        # --- Schema Migrations ---
        # Add any columns that exist in the model but may be missing from an older DB.
        # Each migration is guarded by a column existence check so it's safe to run repeatedly.
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        user_cols = {col["name"] for col in inspector.get_columns("users")}

        # All column migrations for the users table as (column_name, DDL fragment) tuples.
        # These are applied in order; each is skipped if the column already exists.
        user_migrations = [
            ("google_id",              "VARCHAR(255) UNIQUE"),
            ("profile_type",           "VARCHAR(20)"),
            ("profile_status",         "VARCHAR(20) DEFAULT 'pending'"),
            ("title",                  "VARCHAR(100)"),
            ("organization",           "VARCHAR(200)"),
            ("linked_in_url",          "VARCHAR(500)"),
            ("bio",                    "TEXT"),
            ("profile_image",          "VARCHAR(500)"),
            ("geographic_focus",       "VARCHAR(200)"),
            ("investment_stage",       "VARCHAR(100)"),
            ("target_return",          "VARCHAR(100)"),
            ("check_size_min",         "NUMERIC(15,2)"),
            ("check_size_max",         "NUMERIC(15,2)"),
            ("risk_tolerance",         "VARCHAR(20)"),
            ("strategic_interest",     "VARCHAR(100)"),
            ("service_types",          "VARCHAR(200)"),
            ("geographic_service_area","VARCHAR(200)"),
            ("years_of_experience",    "VARCHAR(50)"),
            ("certifications",         "TEXT"),
            ("average_project_size",   "NUMERIC(15,2)"),
            ("development_focus",      "VARCHAR(100)"),
            ("development_type",       "VARCHAR(100)"),
            ("team_size",              "INTEGER"),
            ("portfolio_value",        "NUMERIC(15,2)"),
        ]
        for col_name, col_def in user_migrations:
            if col_name not in user_cols:
                db.session.execute(text(
                    f"ALTER TABLE users ADD COLUMN {col_name} {col_def}"
                ))

        # Make password_hash nullable to support Google-only accounts (no password set)
        if "password_hash" in user_cols:
            db.session.execute(text(
                "ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL"
            ))

        # --- work_orders table migrations ---
        # Phase 4 added description and photo_url; older production DBs may be missing them.
        if inspector.has_table("work_orders"):
            wo_cols = {col["name"] for col in inspector.get_columns("work_orders")}
            work_order_migrations = [
                ("description", "TEXT"),
                ("photo_url",   "VARCHAR(500)"),
                ("created_at",  "TIMESTAMP DEFAULT NOW()"),
            ]
            for col_name, col_def in work_order_migrations:
                if col_name not in wo_cols:
                    db.session.execute(text(
                        f"ALTER TABLE work_orders ADD COLUMN {col_name} {col_def}"
                    ))

        # --- risk_flags table migrations ---
        # resolved_at was added in Phase 4; guard it the same way.
        if inspector.has_table("risk_flags"):
            rf_cols = {col["name"] for col in inspector.get_columns("risk_flags")}
            risk_flag_migrations = [
                ("resolved_at", "TIMESTAMP"),
                ("created_at",  "TIMESTAMP DEFAULT NOW()"),
            ]
            for col_name, col_def in risk_flag_migrations:
                if col_name not in rf_cols:
                    db.session.execute(text(
                        f"ALTER TABLE risk_flags ADD COLUMN {col_name} {col_def}"
                    ))

        # --- portfolios table migration ---
        # Add user_id column to portfolios for user-scoped data isolation
        if inspector.has_table("portfolios"):
            port_cols = {col["name"] for col in inspector.get_columns("portfolios")}
            if "user_id" not in port_cols:
                db.session.execute(text(
                    "ALTER TABLE portfolios ADD COLUMN user_id INTEGER REFERENCES users(id)"
                ))

        # --- investors table migration ---
        # Add user_id column to investors for user-scoped data isolation
        if inspector.has_table("investors"):
            inv_cols = {col["name"] for col in inspector.get_columns("investors")}
            if "user_id" not in inv_cols:
                db.session.execute(text(
                    "ALTER TABLE investors ADD COLUMN user_id INTEGER REFERENCES users(id)"
                ))

        db.session.commit()

        # Auto-seed demo data if no users exist in the database.
        # This is safe because seed_demo_data() checks if users already exist first.
        # DISABLE_SEED=true can be set to skip seeding.
        skip_seed = os.environ.get("DISABLE_SEED", "").lower() in ("1", "true", "yes")
        if not skip_seed:
            seed_demo_data()

    # --- CLI Commands ---
    # Register custom Flask CLI commands for database management

    @app.cli.command("seed")
    def seed_command():
        """Seed the database with demo users, projects, deals, milestones, and vendors.

        Usage:
            flask seed

        Safe to run multiple times — skips seeding if users already exist.
        """
        seed_demo_data()
        print("Database seeded with demo data.")

    return app


def seed_demo_data(force=False):
    """
    Populate the database with demo data for development and testing.

    Seeds the following:
      - 3 user accounts (Sponsor Admin, Project Manager, General Contractor)
      - 1 portfolio with 3 assets across different markets
      - 3 projects in different phases (Construction, Pre-Dev, Stabilization)
      - 3 deals with varying capital raise progress
      - 5 investor profiles with diverse preferences
      - 8 milestones across all projects (some with risk flags)
      - 5 vendors across all assets

    Args:
        force: If True, bypasses the user count guard and re-seeds all demo data.
               Use with caution in production as it may create duplicate data.

    Skips seeding if any users already exist (idempotent), unless force=True.
    """
    from app.models import User, Portfolio, Asset, Project, Deal, Investor, Allocation, Milestone, Vendor, WorkOrder, RiskFlag

    # --- Demo User Accounts ---
    # Each account represents a different role for testing role-based access

    # Always create admin user if not exists
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email="admin@capitalops.io",
            role="sponsor_admin",
            full_name="Admin User",
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.flush()  # Flush to generate admin.id before Portfolio creation

    # Guard: Only seed demo data if database is completely empty (or force=True)
    if not force and User.query.count() > 1:  # More than just the admin we just created
        return

    admin = User.query.filter_by(username="admin").first()

    # Project Manager — access to Execution Control only
    pm = User(
        username="pm",
        email="pm@capitalops.io",
        role="project_manager",
        full_name="Sarah Chen (PM)",
    )
    pm.set_password("pm123")
    db.session.add(pm)

    # General Contractor — limited execution + vendor access
    gc = User(
        username="gc",
        email="gc@capitalops.io",
        role="general_contractor",
        full_name="Mike Torres (GC)",
    )
    gc.set_password("gc123")
    db.session.add(gc)

    # --- Portfolio ---
    # Top-level entity; all assets/projects belong to a portfolio.
    # PortfolioID is included on all entities to enable future multi-portfolio scaling.
    # user_id is set to admin.id (created above) to satisfy NOT NULL constraint.
    portfolio = Portfolio(user_id=admin.id, name="Core Portfolio", description="Primary real estate development portfolio")
    db.session.add(portfolio)
    db.session.flush()  # Flush to generate portfolio.id for foreign keys

    # --- Assets ---
    # Three real estate properties across different markets and asset types

    asset1 = Asset(
        portfolio_id=portfolio.id,
        name="The Meridian",
        location="Austin, TX",
        asset_type="Multifamily",
        square_footage=185000,
        status="Active",
        asset_manager="Julian",
    )
    asset2 = Asset(
        portfolio_id=portfolio.id,
        name="Parkside Commons",
        location="Denver, CO",
        asset_type="Mixed-Use",
        square_footage=120000,
        status="Pre-dev",
        asset_manager="Julian",
    )
    asset3 = Asset(
        portfolio_id=portfolio.id,
        name="Harbor Point",
        location="Miami, FL",
        asset_type="Commercial",
        square_footage=95000,
        status="Active",
        asset_manager="Julian",
    )
    db.session.add_all([asset1, asset2, asset3])
    db.session.flush()  # Flush to generate asset IDs

    # --- Projects ---
    # Each project is linked to one asset and represents a development effort

    from datetime import date

    # Project 1: Active construction, in progress
    project1 = Project(
        asset_id=asset1.id,
        portfolio_id=portfolio.id,
        phase="Construction",
        start_date=date(2025, 6, 1),
        target_completion=date(2026, 12, 31),
        budget_total=28500000,
        budget_actual=12400000,
        status="In Progress",
        pm_assigned="Sarah Chen",
    )
    # Project 2: Early-stage pre-development, planning
    project2 = Project(
        asset_id=asset2.id,
        portfolio_id=portfolio.id,
        phase="Pre-Development",
        start_date=date(2025, 9, 1),
        target_completion=date(2027, 6, 30),
        budget_total=18200000,
        budget_actual=1850000,
        status="Planning",
        pm_assigned="Sarah Chen",
    )
    # Project 3: Stabilization phase, on hold pending resolution
    project3 = Project(
        asset_id=asset3.id,
        portfolio_id=portfolio.id,
        phase="Stabilization",
        start_date=date(2024, 1, 15),
        target_completion=date(2026, 6, 30),
        budget_total=14800000,
        budget_actual=13200000,
        status="On Hold",
        pm_assigned="Mike Torres",
    )
    db.session.add_all([project1, project2, project3])
    db.session.flush()  # Flush to generate project IDs

    # --- Deals ---
    # Each deal represents a capital raise structure tied to a project

    # Deal 1: Active raise, 67% funded
    deal1 = Deal(
        project_id=project1.id,
        portfolio_id=portfolio.id,
        capital_required=28500000,
        capital_raised=19200000,
        return_profile="18-22% IRR",
        duration="36 months",
        risk_level="Medium",
        complexity="Complex",
        phase="Fundraising",
        status="Active",
    )
    # Deal 2: Early stage raise, draft
    deal2 = Deal(
        project_id=project2.id,
        portfolio_id=portfolio.id,
        capital_required=18200000,
        capital_raised=4500000,
        return_profile="15-18% IRR",
        duration="48 months",
        risk_level="High",
        complexity="Moderate",
        phase="Pre-Marketing",
        status="Draft",
    )
    # Deal 3: Fully funded
    deal3 = Deal(
        project_id=project3.id,
        portfolio_id=portfolio.id,
        capital_required=14800000,
        capital_raised=14800000,
        return_profile="12-15% IRR",
        duration="24 months",
        risk_level="Low",
        complexity="Simple",
        phase="Closed",
        status="Funded",
    )
    db.session.add_all([deal1, deal2, deal3])
    db.session.flush()  # Flush to generate deal IDs

    # --- Investors ---
    # Five investor profiles with varying preferences, check sizes, and tiers.
    # These are used by the deal-investor matching engine in Module 1.

    investors = [
        Investor(name="Westfield Capital Partners", accreditation_status="Qualified Purchaser", check_size_min=500000, check_size_max=5000000, asset_preference="Multifamily", geography_preference="Sun Belt", risk_tolerance="Moderate", structure_preference="LP Equity", timeline_preference="24-48 months", strategic_interest="Value-Add", tier_level="Tier 2", status="Active"),
        Investor(name="Angela Moretti", accreditation_status="Accredited", check_size_min=100000, check_size_max=500000, asset_preference="Multifamily", geography_preference="Southeast", risk_tolerance="Conservative", structure_preference="Preferred Equity", timeline_preference="12-36 months", strategic_interest="Cash Flow", tier_level="Tier 1", status="Active"),
        Investor(name="Horizon Family Office", accreditation_status="Qualified Purchaser", check_size_min=1000000, check_size_max=10000000, asset_preference="Commercial", geography_preference="National", risk_tolerance="Aggressive", structure_preference="JV Equity", timeline_preference="36-60 months", strategic_interest="Development", tier_level="Tier 2", status="Active"),
        Investor(name="Thomas Blackwell", accreditation_status="Accredited", check_size_min=250000, check_size_max=1000000, asset_preference="Mixed-Use", geography_preference="Mid-Atlantic", risk_tolerance="Moderate", structure_preference="LP Equity", timeline_preference="18-36 months", strategic_interest="Stabilized", tier_level="Tier 1", status="Prospect"),
        Investor(name="Pacific Ridge Investments", accreditation_status="Qualified Purchaser", check_size_min=2000000, check_size_max=15000000, asset_preference="Mixed-Use", geography_preference="West Coast", risk_tolerance="Aggressive", structure_preference="Co-GP", timeline_preference="48-72 months", strategic_interest="Ground-Up", tier_level="Tier 2", status="Active"),
    ]
    db.session.add_all(investors)
    db.session.flush()

    # --- Milestones ---
    # Construction and development milestones across all three projects.
    # Some are flagged with risk_flag=True to demonstrate the risk monitoring system.

    milestones = [
        # Project 1 (The Meridian) — Construction milestones
        Milestone(project_id=project1.id, portfolio_id=portfolio.id, name="Foundation Complete", category="Construction", target_date=date(2025, 9, 15), completion_date=date(2025, 9, 20), status="Completed", delay_explanation="5-day weather delay", risk_flag=False),
        Milestone(project_id=project1.id, portfolio_id=portfolio.id, name="Steel Structure", category="Construction", target_date=date(2025, 12, 1), completion_date=None, status="In Progress", delay_explanation=None, risk_flag=False),
        Milestone(project_id=project1.id, portfolio_id=portfolio.id, name="MEP Rough-In", category="Construction", target_date=date(2026, 2, 15), completion_date=None, status="Pending", delay_explanation=None, risk_flag=False),
        Milestone(project_id=project1.id, portfolio_id=portfolio.id, name="Building Envelope", category="Construction", target_date=date(2026, 5, 1), completion_date=None, status="Pending", delay_explanation=None, risk_flag=True),
        # Project 2 (Parkside Commons) — Entitlements milestones
        Milestone(project_id=project2.id, portfolio_id=portfolio.id, name="Entitlements Secured", category="Pre-Development", target_date=date(2025, 11, 1), completion_date=None, status="In Progress", delay_explanation=None, risk_flag=True),
        Milestone(project_id=project2.id, portfolio_id=portfolio.id, name="Design Development", category="Design", target_date=date(2026, 1, 15), completion_date=None, status="Pending", delay_explanation=None, risk_flag=False),
        # Project 3 (Harbor Point) — Stabilization milestones
        Milestone(project_id=project3.id, portfolio_id=portfolio.id, name="Demo Complete", category="Renovation", target_date=date(2025, 3, 15), completion_date=date(2025, 3, 12), status="Completed", delay_explanation=None, risk_flag=False),
        Milestone(project_id=project3.id, portfolio_id=portfolio.id, name="Tenant Improvements", category="Renovation", target_date=date(2025, 8, 30), completion_date=None, status="Delayed", delay_explanation="Supply chain issues with custom millwork", risk_flag=True),
    ]
    db.session.add_all(milestones)

    # --- Vendors ---
    # Service providers assigned to specific assets. Includes COI status
    # and SLA type to demonstrate vendor compliance tracking.

    vendor1 = Vendor(asset_id=asset1.id, portfolio_id=portfolio.id, name="Summit Construction Co.", type="General Contractor", coi_status="Current", sla_type="Standard", performance_score=92)
    vendor2 = Vendor(asset_id=asset1.id, portfolio_id=portfolio.id, name="ProMech HVAC", type="Mechanical", coi_status="Current", sla_type="Priority", performance_score=88)
    vendor3 = Vendor(asset_id=asset2.id, portfolio_id=portfolio.id, name="Urban Electric LLC", type="Electrical", coi_status="Expired", sla_type="Standard", performance_score=75)
    vendor4 = Vendor(asset_id=asset3.id, portfolio_id=portfolio.id, name="Coastal Plumbing", type="Plumbing", coi_status="Current", sla_type="Standard", performance_score=85)
    vendor5 = Vendor(asset_id=asset3.id, portfolio_id=portfolio.id, name="SafeGuard Fire Systems", type="Fire Protection", coi_status="Current", sla_type="Priority", performance_score=95)
    db.session.add_all([vendor1, vendor2, vendor3, vendor4, vendor5])
    db.session.flush()

    # --- Allocations ---
    # Investor commitments to specific deals. Demonstrates soft/hard commit
    # tracking and the status flow from Pending through Funded.

    allocations = [
        Allocation(investor_id=investors[0].id, deal_id=deal1.id, soft_commit_amount=2000000, hard_commit_amount=1500000, status="Hard Commit", notes="Completed DD, signed subscription"),
        Allocation(investor_id=investors[1].id, deal_id=deal1.id, soft_commit_amount=350000, hard_commit_amount=350000, status="Funded", notes="Wire confirmed"),
        Allocation(investor_id=investors[2].id, deal_id=deal1.id, soft_commit_amount=5000000, hard_commit_amount=0, status="Soft Commit", notes="Awaiting IC approval"),
        Allocation(investor_id=investors[4].id, deal_id=deal1.id, soft_commit_amount=3000000, hard_commit_amount=3000000, status="Funded", notes=None),
        Allocation(investor_id=investors[2].id, deal_id=deal3.id, soft_commit_amount=2000000, hard_commit_amount=2000000, status="Funded", notes=None),
        Allocation(investor_id=investors[0].id, deal_id=deal3.id, soft_commit_amount=1000000, hard_commit_amount=1000000, status="Funded", notes=None),
        Allocation(investor_id=investors[3].id, deal_id=deal2.id, soft_commit_amount=500000, hard_commit_amount=0, status="Pending", notes="Initial interest expressed"),
    ]
    db.session.add_all(allocations)

    # --- Work Orders ---
    # Vendor assignments demonstrating CapEx/OpEx classification and priority levels.

    work_orders = [
        WorkOrder(vendor_id=vendor1.id, asset_id=asset1.id, portfolio_id=portfolio.id, type="Construction", priority="High", cost=125000, capex_flag=True, status="In Progress"),
        WorkOrder(vendor_id=vendor2.id, asset_id=asset1.id, portfolio_id=portfolio.id, type="HVAC Installation", priority="Medium", cost=45000, capex_flag=True, status="Open"),
        WorkOrder(vendor_id=vendor3.id, asset_id=asset2.id, portfolio_id=portfolio.id, type="Electrical Upgrade", priority="High", cost=32000, capex_flag=True, status="In Progress"),
        WorkOrder(vendor_id=vendor5.id, asset_id=asset3.id, portfolio_id=portfolio.id, type="Fire Alarm", priority="Urgent", cost=8500, capex_flag=False, status="Open"),
    ]
    db.session.add_all(work_orders)

    # --- Risk Flags ---
    # Standalone risk events tied to projects. Demonstrates category-based
    # risk tracking for the governance dashboard.

    risk_flags = [
        RiskFlag(project_id=project1.id, portfolio_id=portfolio.id, category="Schedule", severity="Medium", description="Building envelope timeline at risk due to steel delivery delays", status="Open"),
        RiskFlag(project_id=project2.id, portfolio_id=portfolio.id, category="Regulatory", severity="High", description="Entitlement hearing postponed, potential 60-day delay", status="Open"),
        RiskFlag(project_id=project3.id, portfolio_id=portfolio.id, category="Supply Chain", severity="Medium", description="Custom millwork vendor experiencing production delays", status="Open"),
        RiskFlag(project_id=project1.id, portfolio_id=portfolio.id, category="Budget", severity="Low", description="Minor cost overrun on foundation work, within contingency", status="Mitigated"),
    ]
    db.session.add_all(risk_flags)

    # Commit all seeded data in a single transaction
    db.session.commit()
