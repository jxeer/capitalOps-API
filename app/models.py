"""
CapitalOps API - Database Models

Defines all SQLAlchemy ORM models for the CapitalOps data layer.
The schema follows the operational blueprint's 10 core entities, with every
entity carrying a portfolio_id foreign key to support future multi-portfolio scaling.

Entity Hierarchy:
    Portfolio (top-level)
      └── Asset (real estate property)
            ├── Project (development effort)
            │     ├── Deal (capital raise structure)
            │     │     └── Allocation (investor commitment)
            │     ├── Milestone (progress tracking)
            │     └── RiskFlag (risk event tracking)
            └── Vendor (service provider)
                  └── WorkOrder (assigned work)

Data Flow (per blueprint):
    Module 3 (Vendor/WorkOrder) → Module 2 (Milestone/RiskFlag) → Module 1 (Deal/Allocation)
    Operational truth → Governance interpretation → Investor transparency
"""

from app import db
from app.utils.encryption import EncryptedString
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
import secrets


class User(db.Model):
    """
    Application user with role-based access control.
    
    This model represents all users of the CapitalOps platform, whether they
    authenticate via username/password or via Google OAuth.
    
    AUTHENTICATION:
    - Users authenticate via /api/v1/auth/login and receive a JWT
    - JWT contains user ID and role for authorization
    - Password hashes use Werkzeug's secure hasher (not reversible)
    - Google OAuth users have google_id set but no password_hash
    
    ROLES AND PERMISSIONS:
    Each role has specific module access defined in ROLE_PERMISSIONS:
    - sponsor_admin:      Full access to all modules + admin actions
    - project_manager:     Execution Control module only
    - general_contractor:   Limited Execution + limited Vendor access
    - vendor:              Vendor module (own work orders only)
    - investor_tier1:      Capital module (view deals, submit allocations)
    - investor_tier2:      Capital module with priority access + enhanced reporting
    
    PROFILE TYPES:
    Users can have different profile types that describe their organization:
    - investor:  Institutional or individual investors
    - vendor:    Service providers (contractors, etc.)
    - developer: Real estate developers
    
    Attributes:
        id: Primary key
        username: Unique username for login
        email: Unique email address (required for password-based login)
        password_hash: Werkzeug hash of password (null for Google-only accounts)
        role: Permission role key
        full_name: Display name for UI
        google_id: Google OAuth subject ID (set when signing in via Google)
        profile_type: Type of organization (investor/vendor/developer)
        profile_status: Account status (pending/active/inactive/suspended)
        profile_image: URL to profile image (uploaded to S3)
        
    SECURITY NOTES:
    - Email is required for password-based login (needed for MFA codes)
    - Google-only accounts cannot use password reset (no password_hash)
    - Role permissions are checked at the route level via has_permission()
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Werkzeug-hashed password. Nullable because Google OAuth users don't have passwords.
    # Use set_password() and check_password() methods to work with hashes.
    password_hash = db.Column(db.String(256), nullable=True)
    # Role determines module access permissions (see ROLE_PERMISSIONS below)
    role = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(150))  # Display name shown in UI
    # Google OAuth subject ID - set when user signs in via Google
    # If set, user can sign in with Google without needing a password
    google_id = db.Column(db.String(255), unique=True, nullable=True)

    # Profile fields (Phase 4 - Profile Enhancement)
    profile_type = db.Column(db.String(20))                    # "investor", "vendor", "developer"
    profile_status = db.Column(db.String(20), default="pending")  # "pending", "active", "inactive", "suspended"
    title = db.Column(db.String(100))
    organization = db.Column(db.String(200))
    linked_in_url = db.Column(db.String(500))
    bio = db.Column(db.Text)
    
    profile_image = db.Column(db.String(500))
    
    # Investor-specific fields
    geographic_focus = db.Column(db.String(200))
    investment_stage = db.Column(db.String(100))
    target_return = db.Column(db.String(100))
    check_size_min = db.Column(db.Numeric(15, 2))
    check_size_max = db.Column(db.Numeric(15, 2))
    risk_tolerance = db.Column(db.String(20))                  # "Conservative", "Moderate", "Aggressive"
    strategic_interest = db.Column(db.String(100))
    
    # Vendor-specific fields
    service_types = db.Column(db.String(200))
    geographic_service_area = db.Column(db.String(200))
    years_of_experience = db.Column(db.String(50))
    certifications = db.Column(db.Text)
    average_project_size = db.Column(db.Numeric(15, 2))
    
    # Developer-specific fields
    development_focus = db.Column(db.String(100))
    development_type = db.Column(db.String(100))
    team_size = db.Column(db.Integer)
    portfolio_value = db.Column(db.Numeric(15, 2))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        """Hash and store a plaintext password using Werkzeug's secure hasher."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify a plaintext password against the stored hash.

        Returns False if the user has no password hash (Google-only account).
        """
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    # Maps each role to a list of permission keys.
    # Used by has_permission() to check access at the route level.
    ROLE_PERMISSIONS = {
        "sponsor_admin": ["capital", "execution", "vendor", "admin"],
        "project_manager": ["execution"],
        "general_contractor": ["execution_limited", "vendor_limited"],
        "vendor": ["vendor_self"],
        "investor_tier1": ["capital_view"],
        "investor_tier2": ["capital_view", "capital_priority"],
    }

    def has_permission(self, perm):
        """Check if the user's role includes a specific permission key."""
        return perm in self.ROLE_PERMISSIONS.get(self.role, [])

    @property
    def role_display(self):
        """Return a human-readable label for the user's role."""
        labels = {
            "sponsor_admin": "Sponsor Admin",
            "project_manager": "Project Manager",
            "general_contractor": "General Contractor",
            "vendor": "Vendor",
            "investor_tier1": "Investor (Tier 1)",
            "investor_tier2": "Priority Investor (Tier 2)",
        }
        return labels.get(self.role, self.role)

    def to_dict(self):
        """Serialize user to a JSON-safe dictionary (excludes password hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "role_display": self.role_display,
            "full_name": self.full_name,
            "google_id": self.google_id,
            "has_password": self.password_hash is not None,

            # Profile fields (Phase 4)
            "profileType": self.profile_type,
            "profileStatus": self.profile_status,
            "title": self.title,
            "organization": self.organization,
            "linkedInUrl": self.linked_in_url,
            "bio": self.bio,
            "profileImage": self.profile_image,
            
            # Investor-specific
            "geographicFocus": self.geographic_focus,
            "investmentStage": self.investment_stage,
            "targetReturn": self.target_return,
            "checkSizeMin": float(self.check_size_min) if self.check_size_min else None,
            "checkSizeMax": float(self.check_size_max) if self.check_size_max else None,
            "riskTolerance": self.risk_tolerance,
            "strategicInterest": self.strategic_interest,
            
            # Vendor-specific
            "serviceTypes": self.service_types,
            "geographicServiceArea": self.geographic_service_area,
            "yearsOfExperience": self.years_of_experience,
            "certifications": self.certifications,
            "averageProjectSize": float(self.average_project_size) if self.average_project_size else None,
            
            # Developer-specific
            "developmentFocus": self.development_focus,
            "developmentType": self.development_type,
            "teamSize": self.team_size,
            "portfolioValue": float(self.portfolio_value) if self.portfolio_value else None,
            
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Portfolio(db.Model):
    """
    Top-level entity representing a real estate portfolio.

    Currently only one portfolio exists, but the schema is designed so that
    all downstream entities carry a portfolio_id for future multi-portfolio expansion
    without requiring a schema rewrite.
    
    Each portfolio is owned by a specific user (user_id).
    """
    __tablename__ = "portfolios"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # Owner
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # One portfolio has many assets
    assets = db.relationship("Asset", backref="portfolio", lazy=True)
    
    # Relationship to owner user
    owner = db.relationship("User", backref="portfolios")

    def to_dict(self):
        """Serialize portfolio to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Asset(db.Model):
    """
    A real estate property within a portfolio.

    Represents a physical property with key attributes like location,
    asset type (Multifamily, Mixed-Use, Commercial, etc.), and status.

    Each asset can have multiple projects and vendors assigned to it.
    """
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    portfolio_id = db.Column(db.Integer, db.ForeignKey("portfolios.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)        # Property name (e.g., "The Meridian")
    location = db.Column(db.String(300))                     # City, State
    asset_type = db.Column(db.String(100))                   # Multifamily, Mixed-Use, Commercial, etc.
    square_footage = db.Column(db.Integer)                   # Total building square footage
    status = db.Column(db.String(50))                        # Pre-dev, Active, or Stabilized
    asset_manager = db.Column(db.String(150))                # Name of assigned asset manager
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Media: JSON array of {url, type, name} objects (base64 data URLs or external URLs)
    media = db.Column(db.JSON, default=list)

    # One asset can have multiple development projects
    projects = db.relationship("Project", backref="asset", lazy=True)
    # One asset can have multiple vendors assigned
    vendors = db.relationship("Vendor", backref="asset", lazy=True)

    def to_dict(self):
        """Serialize asset to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "portfolio_id": self.portfolio_id,
            "name": self.name,
            "location": self.location,
            "asset_type": self.asset_type,
            "square_footage": self.square_footage,
            "status": self.status,
            "asset_manager": self.asset_manager,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "media": self.media or [],
        }


class Project(db.Model):
    """
    A development project tied to a specific asset.

    Tracks the project lifecycle including phase, budget, timeline, and
    assigned project manager. Projects are the central hub connecting
    deals (capital) and milestones (execution) to an asset.
    """
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey("portfolios.id"), nullable=False)
    phase = db.Column(db.String(100))           # Construction, Pre-Development, Stabilization, etc.
    start_date = db.Column(db.Date)
    target_completion = db.Column(db.Date)
    budget_total = db.Column(db.Numeric(15, 2)) # Total approved budget
    budget_actual = db.Column(db.Numeric(15, 2)) # Actual spend to date
    status = db.Column(db.String(50))           # On Track, At Risk, Complete, etc.
    pm_assigned = db.Column(db.String(150))     # Name of assigned project manager
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Media: JSON array of {url, type, name} objects (base64 data URLs or external URLs)
    media = db.Column(db.JSON, default=list)

    # One project can have multiple deals (capital raise structures)
    deals = db.relationship("Deal", backref="project", lazy=True)
    # One project has many milestones for progress tracking
    milestones = db.relationship("Milestone", backref="project", lazy=True)

    def to_dict(self):
        """Serialize project to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "asset_name": self.asset.name if self.asset else None,
            "portfolio_id": self.portfolio_id,
            "phase": self.phase,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "target_completion": self.target_completion.isoformat() if self.target_completion else None,
            "budget_total": float(self.budget_total or 0),
            "budget_actual": float(self.budget_actual or 0),
            "status": self.status,
            "pm_assigned": self.pm_assigned,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "media": self.media or [],
        }


class Deal(db.Model):
    """
    A capital raise structure tied to a project.

    Represents the investment opportunity presented to investors.
    Tracks how much capital is needed, how much has been raised,
    the return profile, risk level, and current status.

    This is the core entity in Module 1 (Capital Engine) that gets
    matched to investors and receives allocations.
    """
    __tablename__ = "deals"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey("portfolios.id"), nullable=False)
    capital_required = db.Column(db.Numeric(15, 2))  # Total capital needed for the deal
    capital_raised = db.Column(db.Numeric(15, 2))    # Capital committed/raised so far
    return_profile = db.Column(db.String(100))       # Expected returns (e.g., "18-22% IRR")
    duration = db.Column(db.String(100))             # Investment duration (e.g., "36 months")
    risk_level = db.Column(db.String(50))            # Low, Medium, Medium-High, High
    complexity = db.Column(db.String(50))            # Low, Medium, High
    phase = db.Column(db.String(100))                # Active Raise, Early Stage, Fully Allocated
    status = db.Column(db.String(50))                # Open or Closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # One deal can have many investor allocations
    allocations = db.relationship("Allocation", backref="deal", lazy=True)

    def to_dict(self):
        """Serialize deal to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "project_name": self.project.asset.name if self.project and self.project.asset else None,
            "portfolio_id": self.portfolio_id,
            "capital_required": float(self.capital_required or 0),
            "capital_raised": float(self.capital_raised or 0),
            "return_profile": self.return_profile,
            "duration": self.duration,
            "risk_level": self.risk_level,
            "complexity": self.complexity,
            "phase": self.phase,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Investor(db.Model):
    """
    An investor profile with preferences used for deal matching.

    Stores investor attributes that the Capital Engine's matching logic
    evaluates against open deals.

    Tier levels:
        - Tier 1: Standard investor access
        - Tier 2: Priority investor with early access and enhanced reporting
    """
    __tablename__ = "investors"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # Owner (optional for shared investors)
    name = db.Column(db.String(200), nullable=False)
    accreditation_status = db.Column(db.String(50))     # Verified or Pending
    check_size_min = db.Column(db.Numeric(15, 2))       # Minimum investment amount
    check_size_max = db.Column(db.Numeric(15, 2))       # Maximum investment amount
    asset_preference = db.Column(db.String(100))        # Preferred asset type (or "All")
    geography_preference = db.Column(db.String(200))    # Preferred geography/market
    risk_tolerance = db.Column(db.String(50))           # Low, Low-Medium, Medium, Medium-High, High
    structure_preference = db.Column(db.String(100))    # LP Equity, Preferred Equity, Debt, Mezzanine
    timeline_preference = db.Column(db.String(100))     # Preferred hold period (e.g., "3-5 years")
    strategic_interest = db.Column(db.String(100))      # Value-Add, Core-Plus, Opportunistic, Income
    tier_level = db.Column(db.String(20))               # "Tier 1" or "Tier 2"
    status = db.Column(db.String(50))                   # Active or Pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Encrypted PII/financial fields
    tax_id = db.Column(EncryptedString(20))             # SSN or EIN
    date_of_birth = db.Column(EncryptedString(20))     # DOB
    phone = db.Column(EncryptedString(20))              # Contact phone
    bank_account_number = db.Column(EncryptedString(50))  # Bank account for distributions
    routing_number = db.Column(EncryptedString(20))     # Bank routing number

    # One investor can have multiple allocations across deals
    allocations = db.relationship("Allocation", backref="investor", lazy=True)

    def to_dict(self):
        """Serialize investor to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "accreditation_status": self.accreditation_status,
            "check_size_min": float(self.check_size_min or 0),
            "check_size_max": float(self.check_size_max or 0),
            "asset_preference": self.asset_preference,
            "geography_preference": self.geography_preference,
            "risk_tolerance": self.risk_tolerance,
            "structure_preference": self.structure_preference,
            "timeline_preference": self.timeline_preference,
            "strategic_interest": self.strategic_interest,
            "tier_level": self.tier_level,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Allocation(db.Model):
    """
    An investor's capital commitment to a specific deal.

    Tracks both soft commits (verbal/preliminary) and hard commits (legally binding).
    Status flow: Pending → Approved → Funded (or Declined)
    """
    __tablename__ = "allocations"

    id = db.Column(db.Integer, primary_key=True)
    investor_id = db.Column(db.Integer, db.ForeignKey("investors.id"), nullable=False)
    deal_id = db.Column(db.Integer, db.ForeignKey("deals.id"), nullable=False)
    soft_commit_amount = db.Column(db.Numeric(15, 2))   # Preliminary/verbal commitment amount
    hard_commit_amount = db.Column(db.Numeric(15, 2))   # Legally binding commitment amount
    status = db.Column(db.String(50))                    # Pending, Approved, Funded, Declined
    notes = db.Column(db.Text)                           # Free-text notes from sponsor
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Serialize allocation to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "investor_id": self.investor_id,
            "investor_name": self.investor.name if self.investor else None,
            "deal_id": self.deal_id,
            "soft_commit_amount": float(self.soft_commit_amount or 0),
            "hard_commit_amount": float(self.hard_commit_amount or 0),
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Milestone(db.Model):
    """
    A project milestone for tracking execution progress.

    Used by Module 2 (Execution Control) to provide governance-level
    visibility into project timelines.
    Status flow: Not Started → In Progress → Complete
    """
    __tablename__ = "milestones"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey("portfolios.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)     # Milestone name (e.g., "Foundation Complete")
    category = db.Column(db.String(100))                  # Standardized category (Construction, Entitlements, etc.)
    target_date = db.Column(db.Date)                      # Planned completion date
    completion_date = db.Column(db.Date)                  # Actual completion date (null if not complete)
    status = db.Column(db.String(50))                     # Not Started, In Progress, Complete
    delay_explanation = db.Column(db.Text)                # PM's structured explanation for any delays
    risk_flag = db.Column(db.Boolean, default=False)      # True if milestone is flagged as a risk
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Serialize milestone to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "portfolio_id": self.portfolio_id,
            "name": self.name,
            "category": self.category,
            "target_date": self.target_date.isoformat() if self.target_date else None,
            "completion_date": self.completion_date.isoformat() if self.completion_date else None,
            "status": self.status,
            "delay_explanation": self.delay_explanation,
            "risk_flag": self.risk_flag,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Vendor(db.Model):
    """
    A contractor or service provider assigned to an asset.

    Tracked in Module 3 (Asset & Vendor Control) for operational discipline.
    Includes COI compliance, SLA type, and performance scoring.
    """
    __tablename__ = "vendors"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey("portfolios.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)     # Vendor/company name
    type = db.Column(db.String(100))                      # Trade type (Electrical, Mechanical, Plumbing, etc.)
    coi_status = db.Column(db.String(50))                 # Current, Expired, or Pending
    sla_type = db.Column(db.String(50))                   # Standard or Priority
    performance_score = db.Column(db.Integer)             # 0-100 score for vendor performance
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # One vendor can have multiple work orders
    work_orders = db.relationship("WorkOrder", backref="vendor", lazy=True)

    def to_dict(self):
        """Serialize vendor to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "asset_name": self.asset.name if self.asset else None,
            "portfolio_id": self.portfolio_id,
            "name": self.name,
            "type": self.type,
            "coi_status": self.coi_status,
            "sla_type": self.sla_type,
            "performance_score": self.performance_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WorkOrder(db.Model):
    """
    A work assignment for a vendor on a specific asset.

    Tracks vendor-assigned work including type, priority, cost, and
    CapEx vs OpEx classification.
    """
    __tablename__ = "work_orders"

    id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendors.id"), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey("portfolios.id"), nullable=False)
    type = db.Column(db.String(100))                 # Work type (Maintenance, Repair, Installation, etc.)
    priority = db.Column(db.String(50))              # Normal, High, or Urgent
    cost = db.Column(db.Numeric(15, 2))              # Estimated or actual cost
    capex_flag = db.Column(db.Boolean, default=False) # True = Capital Expenditure, False = Operating Expense
    status = db.Column(db.String(50))                # Open, In Progress, Complete, Cancelled
    completion_date = db.Column(db.Date)             # Date work was completed
    description = db.Column(db.Text)                 # Free-text description of the work to be done
    photo_url = db.Column(db.String(500))            # URL for completion photo documentation
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Serialize work order to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor.name if self.vendor else None,
            "asset_id": self.asset_id,
            "portfolio_id": self.portfolio_id,
            "type": self.type,
            "priority": self.priority,
            "cost": float(self.cost or 0),
            "capex_flag": self.capex_flag,
            "status": self.status,
            "completion_date": self.completion_date.isoformat() if self.completion_date else None,
            "description": self.description,
            "photo_url": self.photo_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class RiskFlag(db.Model):
    """
    A risk event associated with a project.

    Provides category-based risk tracking for standardized risk reporting.
    Status flow: Open → Resolved
    """
    __tablename__ = "risk_flags"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    portfolio_id = db.Column(db.Integer, db.ForeignKey("portfolios.id"), nullable=False)
    category = db.Column(db.String(100))             # Risk category (Schedule, Budget, Compliance, etc.)
    severity = db.Column(db.String(50))              # Low, Medium, or High
    description = db.Column(db.Text)                 # Detailed description of the risk
    status = db.Column(db.String(50), default="Open") # Open or Resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)             # Timestamp when the risk was resolved

    def to_dict(self):
        """Serialize risk flag to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "portfolio_id": self.portfolio_id,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class ConnectionRequest(db.Model):
    """
    A connection request between two users.
    
    Status flow: pending → accepted/declined
    """
    __tablename__ = "connection_requests"
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # "pending", "accepted", "declined"
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime)
    
    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_connection_requests")
    receiver = db.relationship("User", foreign_keys=[receiver_id], backref="received_connection_requests")
    
    def to_dict(self):
        """Serialize connection request to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "senderId": self.sender_id,
            "receiverId": self.receiver_id,
            "senderName": self.sender.full_name if self.sender else None,
            "receiverName": self.receiver.full_name if self.receiver else None,
            "status": self.status,
            "message": self.message,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "respondedAt": self.responded_at.isoformat() if self.responded_at else None,
        }


class Conversation(db.Model):
    """
    A 1-on-1 conversation between two users.
    """
    __tablename__ = "conversations"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id1 = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user_id2 = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user1 = db.relationship("User", foreign_keys=[user_id1])
    user2 = db.relationship("User", foreign_keys=[user_id2])
    
    def to_dict(self):
        """Serialize conversation to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "userId1": self.user_id1,
            "userId2": self.user_id2,
            "user1Name": self.user1.full_name if self.user1 else None,
            "user2Name": self.user2.full_name if self.user2 else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
        }


class Message(db.Model):
    """
    An individual message in a conversation.
    """
    __tablename__ = "messages"
    
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversations.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    read_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship("User", foreign_keys=[sender_id])
    conversation = db.relationship("Conversation", backref="messages")
    
    def to_dict(self):
        """Serialize message to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "conversationId": self.conversation_id,
            "senderId": self.sender_id,
            "senderName": self.sender.full_name if self.sender else None,
            "content": self.content,
            "readAt": self.read_at.isoformat() if self.read_at else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
        }


class PasswordResetToken(db.Model):
    """
    A single-use password reset token sent to a user's email.

    SECURITY CHARACTERISTICS:
    - Tokens are URL-safe base64 strings (43 characters, cryptographically random)
    - Valid for 30 minutes from creation
    - Single-use: marked as used immediately after successful password reset
    - Tied to specific user account (cannot be used for different user)
    - Stored as SHA-256 hash for security

    USAGE:
    1. User requests password reset via /api/v1/auth/forgot-password
    2. Server generates token and stores hash in this table
    3. Server sends email with reset link containing plaintext token
    4. User clicks link and submits new password via /api/v1/auth/reset-password
    5. Server validates token (exists, not expired, not used) and updates password
    6. Token is marked as used (cannot be reused)

    Attributes:
        id: Primary key
        user_id: Foreign key to users table
        token_hash: SHA-256 hash of the plaintext token (stored, never plaintext)
        expires_at: When token expires (default 30 minutes from creation)
        used: Whether token has been used (single-use)
        created_at: When token was generated

    Security:
        - Token stored as SHA-256 hash (one-way, not reversible)
        - Tokens expire after 30 minutes
        - Tokens can only be used once
        - Tokens are tied to specific user accounts
    """
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="password_reset_tokens")

    @classmethod
    def generate_token(cls, user_id, expiry_minutes=30):
        """
        Create and persist a new password reset token for the given user.

        This method:
        1. Generates a cryptographically secure 48-byte random token
        2. Stores SHA-256 hash of the plaintext token in the database
        3. Sets expiration time (default 30 minutes)
        4. Saves to database immediately

        Args:
            user_id: The ID of the user requesting the reset
            expiry_minutes: Minutes until token expires (default 30)

        Returns:
            PasswordResetToken: The newly created and persisted token instance
            (plaintext token is returned for use in email link — caller must send it)
        """
        import hashlib
        import secrets as _secrets
        token = _secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        reset_token = cls(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        db.session.add(reset_token)
        db.session.commit()
        reset_token._plaintext_token = token
        return reset_token

    @property
    def plaintext_token(self):
        """Return the plaintext token (only available immediately after generation)."""
        return getattr(self, "_plaintext_token", None)

    @property
    def is_valid(self):
        """
        Check if the password reset token is valid.

        A token is valid if:
        - It has not been marked as used (single-use)
        - It has not expired (checked against current UTC time)

        Returns:
            bool: True if valid, False otherwise
        """
        return not self.used and datetime.utcnow() < self.expires_at
    def is_valid(self):
        """
        Check if the password reset token is valid.
        
        A token is valid if:
        - It has not been marked as used (single-use protection)
        - It has not expired (checked against current UTC time)
        
        Returns:
            bool: True if valid, False otherwise
        """
        return not self.used and datetime.utcnow() < self.expires_at


# =============================================================================
# MFA CODE MODEL
# =============================================================================
# Used for multi-factor authentication during login.
# 
# SECURITY CHARACTERISTICS:
# - 6-digit numeric code (100,000 possible combinations)
# - Valid for 5 minutes only
# - Single-use (marked as used after successful verification)
# - Associated with specific user (cannot be used for different account)
#
# This model enables MFA by generating and validating codes sent via email.
# After successful login verification, the code is marked as used.

class MfaCode(db.Model):
    """
    A single-use MFA verification code sent to user's email during login.

    When a user successfully enters their username/password, a 6-digit code
    is generated and stored. When they enter the code, it's validated against
    this table and marked as used.

    Attributes:
        id: Primary key
        user_id: Foreign key to users table
        code_hash: SHA-256 hash of the plaintext code (stored, never plaintext)
        expires_at: When the code expires (default 5 minutes from creation)
        used: Whether the code has been used (single-use)
        created_at: When the code was generated

    Security:
        - Codes stored as SHA-256 hash (one-way, not reversible)
        - Codes are 6 digits (100,000 possibilities)
        - Codes expire after 5 minutes
        - Codes can only be used once
        - Codes are tied to specific user accounts
        - Lookup by (user_id, used, expires_at) index for efficiency
    """
    __tablename__ = "mfa_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_attempts = db.Column(db.Integer, default=0)

    user = db.relationship("User", backref="mfa_codes")

    __table_args__ = (
        db.Index("ix_mfa_codes_user_used_expires", "user_id", "used", "expires_at"),
    )

    @classmethod
    def generate_code(cls, user_id, expiry_minutes=5):
        """
        Create and persist a new 6-digit MFA code for the given user.

        This method:
        1. Generates a cryptographically secure 6-digit code
        2. Stores SHA-256 hash in the database
        3. Sets expiration time
        4. Saves to database immediately

        Args:
            user_id: The ID of the user to generate code for
            expiry_minutes: Minutes until code expires (default 5)

        Returns:
            MfaCode: The newly created and persisted MfaCode instance
            (plaintext code is attached as _plaintext_code for email — caller must send it)
        """
        import hashlib
        import secrets as _secrets
        code = "".join([str(_secrets.randbelow(10)) for _ in range(6)])
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        mfa_code = cls(user_id=user_id, code_hash=code_hash, expires_at=expires_at)
        db.session.add(mfa_code)
        db.session.commit()
        mfa_code._plaintext_code = code
        return mfa_code

    @property
    def plaintext_code(self):
        """Return the plaintext code (only available immediately after generation)."""
        return getattr(self, "_plaintext_code", None)

    @property
    def is_valid(self):
        """
        Check if the MFA code is valid for verification.

        A code is valid if:
        - It has not been marked as used (single-use)
        - It has not expired (checked against current UTC time)

        Returns:
            bool: True if valid, False otherwise
        """
        return not self.used and datetime.utcnow() < self.expires_at


class EntitlementRecord(db.Model):
    """
    A permit or entitlement application tied to a project.

    Represents official filings with government agencies for construction permits,
    rezoning, variances, site plan approvals, etc. This data is typically scraped
    from county/city permit portals and linked back to projects.

    Attributes:
        id: Primary key
        project_id: Foreign key to projects table
        parcel_number: Parcel identifier from the county/city
        agency: Issuing agency (e.g., "Miami-Dade County", "City of Austin")
        application_number: Agency's application/permit number
        entitlement_type: Type of entitlement (rezoning, variance, site plan, etc.)
        status: Current status in the approval process
        submitted_date: Date the application was submitted
        hearing_date: Scheduled hearing date (if applicable)
        approved_date: Date of final approval (if approved)
        notes: Additional notes or context
        source_url: URL to the original record on the agency portal
    """
    __tablename__ = "entitlement_records"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    parcel_number = db.Column(db.String(100), nullable=False)
    agency = db.Column(db.String(200), nullable=False)
    application_number = db.Column(db.String(100), nullable=False)
    entitlement_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    submitted_date = db.Column(db.Date, nullable=False)
    hearing_date = db.Column(db.Date, nullable=True)
    approved_date = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    source_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    project = db.relationship("Project", backref="entitlement_records")
    events = db.relationship("PermitEvent", backref="entitlement_record", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "parcel_number": self.parcel_number,
            "agency": self.agency,
            "application_number": self.application_number,
            "entitlement_type": self.entitlement_type,
            "status": self.status,
            "submitted_date": self.submitted_date.isoformat() if self.submitted_date else None,
            "hearing_date": self.hearing_date.isoformat() if self.hearing_date else None,
            "approved_date": self.approved_date.isoformat() if self.approved_date else None,
            "notes": self.notes,
            "source_url": self.source_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class PermitEvent(db.Model):
    """
    A status change or update on an EntitlementRecord.

    Events are written by the scraper when it detects a change, or by a user
    who manually enters an update. Each event captures the before/after state.

    Attributes:
        id: Primary key
        entitlement_record_id: Foreign key to entitlement_records
        event_type: Type of event (status_change, hearing_scheduled, approved, denied)
        previous_value: Previous value before the change
        new_value: New value after the change
        detected_at: When the event was detected/created
        source: Origin of the event ("scraper" or "manual")
    """
    __tablename__ = "permit_events"

    id = db.Column(db.Integer, primary_key=True)
    entitlement_record_id = db.Column(db.Integer, db.ForeignKey("entitlement_records.id"), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    previous_value = db.Column(db.String(200), nullable=True)
    new_value = db.Column(db.String(200), nullable=True)
    detected_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    source = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "entitlement_record_id": self.entitlement_record_id,
            "event_type": self.event_type,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class FieldMedia(db.Model):
    """
    A photo or video uploaded by a vendor tied to a project or work order.

    Media files are stored in S3. This model tracks the S3 key, bucket, and
    metadata. Either project_id or work_order_id must be set.

    Attributes:
        id: Primary key
        project_id: Foreign key to projects (optional)
        work_order_id: Foreign key to work_orders (optional)
        uploaded_by_user_id: Foreign key to users
        media_type: Type of media ("photo" or "video")
        s3_key: S3 object key
        s3_bucket: S3 bucket name
        filename: Original filename
        caption: Optional caption/description
        uploaded_at: When the file was uploaded
    """
    __tablename__ = "field_media"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=True)
    work_order_id = db.Column(db.Integer, db.ForeignKey("work_orders.id"), nullable=True)
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    media_type = db.Column(db.String(20), nullable=False)
    s3_key = db.Column(db.String(500), nullable=False)
    s3_bucket = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    caption = db.Column(db.String(500), nullable=True)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    project = db.relationship("Project", backref="field_media")
    work_order = db.relationship("WorkOrder", backref="field_media")
    uploaded_by_user = db.relationship("User", backref="uploaded_media")

    __table_args__ = (
        db.CheckConstraint(
            "project_id IS NOT NULL OR work_order_id IS NOT NULL",
            name="check_field_media_project_or_work_order"
        ),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "work_order_id": self.work_order_id,
            "uploaded_by_user_id": self.uploaded_by_user_id,
            "media_type": self.media_type,
            "s3_key": self.s3_key,
            "s3_bucket": self.s3_bucket,
            "filename": self.filename,
            "caption": self.caption,
            "uploaded_at": self.uploaded_at.isoformat() if self.uploaded_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Notification(db.Model):
    """
    An alert sent to a user.

    Notifications are created by the system when relevant events occur,
    such as entitlement updates, permit events, or work order assignments.

    Attributes:
        id: Primary key
        user_id: Foreign key to users
        notification_type: Type of notification (entitlement_update, permit_event, etc.)
        title: Short title for the notification
        body: Full notification text
        related_entity_type: Type of related entity (e.g., "entitlement_record")
        related_entity_id: ID of the related entity
        is_read: Whether the user has read this notification
        created_at: When the notification was created
    """
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    related_entity_type = db.Column(db.String(50), nullable=True)
    related_entity_id = db.Column(db.Integer, nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="notifications")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "notification_type": self.notification_type,
            "title": self.title,
            "body": self.body,
            "related_entity_type": self.related_entity_type,
            "related_entity_id": self.related_entity_id,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class FinancialReport(db.Model):
    """
    A financial summary report generated by a Sponsor Admin and shared with another user.

    Reports aggregate data from a project or deal and are delivered via the
    notification system. Both project and deal summaries are supported.

    Attributes:
        id: Primary key
        created_by_user_id: Foreign key to users (report author)
        recipient_user_id: Foreign key to users (report receiver)
        project_id: Foreign key to projects (optional, but one of project_id or deal_id is required)
        deal_id: Foreign key to deals (optional, but one of project_id or deal_id is required)
        report_type: Type of report ("project_summary" or "deal_summary")
        title: Human-readable report title
        content: Structured JSON data with aggregated metrics
        is_read: Whether the recipient has read the report
        created_at: When the report was generated
    """
    __tablename__ = "financial_reports"

    id = db.Column(db.Integer, primary_key=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recipient_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=True)
    deal_id = db.Column(db.Integer, db.ForeignKey("deals.id"), nullable=True)
    report_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.JSON, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    created_by_user = db.relationship("User", foreign_keys=[created_by_user_id], backref="created_financial_reports")
    recipient_user = db.relationship("User", foreign_keys=[recipient_user_id], backref="received_financial_reports")
    project = db.relationship("Project", backref="financial_reports")
    deal = db.relationship("Deal", backref="financial_reports")

    __table_args__ = (
        db.CheckConstraint(
            "project_id IS NOT NULL OR deal_id IS NOT NULL",
            name="check_financial_report_project_or_deal"
        ),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "created_by_user_id": self.created_by_user_id,
            "recipient_user_id": self.recipient_user_id,
            "project_id": self.project_id,
            "deal_id": self.deal_id,
            "report_type": self.report_type,
            "title": self.title,
            "content": self.content,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
