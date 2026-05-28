"""
CapitalOps Demo Data Seeder

Standalone script to populate the database with detailed project data.
Run from the backend root directory:

    python scripts/seed_demo_data.py

Idempotent: checks if a record with the same name already exists before
inserting, and skips it if so. Run safely multiple times.

Use --dry-run to preview what would be created without writing to the database.
"""

import argparse
import sys
import os
from datetime import date, timedelta

# Add backend root to path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import Portfolio, Asset, Project, Vendor, Milestone


ASSETS = [
    ("Atlanta Multi-Asset Portfolio", "South ATL cluster + Westside ATL + Decatur assets", "Atlanta Metro, GA", "Multifamily"),
    ("PadSplit Portfolio (4)", "South ATL cluster", "Atlanta Metro, GA", "Multifamily"),
    ("Grove Park Portfolio", "359 & 371 Lanier Ave NW", "Atlanta, GA", "Multifamily"),
    ("Vine City Portfolio", "Westside ATL", "Atlanta, GA", "Multifamily"),
    ("CBM Section 8 Portfolio", "Penelope + Decatur", "Atlanta / Decatur, GA", "Multifamily"),
    ("Dormplex", "2807 Burton Rd NW", "Atlanta, GA", "Multifamily"),
    ("Duplex 839 Commodore", "839 Commodore Dr NW", "Atlanta, GA", "Residential"),
    ("Duplex 308 Anderson", "308 Anderson Ave NW", "Atlanta, GA", "Residential"),
    ("Duplex 2035 Lois", "2035 Lois Pl NW", "Atlanta, GA", "Residential"),
    ("Boarding House 338 Candler", "338 Candler Rd SE", "Atlanta, GA", "Residential"),
    ("MLK Workforce Townhome Development", "6802 E Dr. Martin Luther King Jr Blvd", "Tampa, FL", "Multifamily"),
    ("705 Wilma Street Workforce Housing", "705 Wilma St", "Tampa, FL", "Multifamily"),
    ("622 W MLK Mixed-Use Workforce Housing", "622 W Dr. Martin Luther King Jr Blvd", "Tampa, FL", "Mixed-Use"),
    ("Genesee Residences", "2909 E Genesee St", "Tampa, FL", "Multifamily"),
    ("Sligh Ave Attainable Housing", "1918-1914 Sligh Ave", "Tampa, FL", "Multifamily"),
    ("370 12th Ave Coastal Residence", "370 12th Ave", "Indian Rocks Beach, FL", "Residential"),
    ("372 12th Ave Coastal Residence", "372 12th Ave", "Indian Rocks Beach, FL", "Residential"),
    ("Earlewood / 301 Sunset Drive Redevelopment", "301 Sunset Drive", "Columbia, SC", "Multifamily"),
    ("Streams at Earlewood", "Earlewood / NOMA Corridor", "Columbia, SC", "Multifamily"),
    ("Gretna Crossroads Mixed-Use Development", "Gretna Crossroads site", "Gretna, FL", "Mixed-Use"),
    ("Pensacola Duplex Development", "523 West Monroe", "Pensacola, FL", "Residential"),
    ("East Tampa Mixed-Use Affordable Housing", "2917 N. 34th Street", "Tampa, FL", "Mixed-Use"),
    ("NEXX Sports & Esports Complex", "Columbia / Irmo concept", "Columbia, SC", "Commercial"),
    ("Starfleet Sports Complex", "Conceptual multi-state site", "TBD", "Commercial"),
    ("Dr. Walter L. Smith Library Redevelopment", "Walter L. Smith Library", "TBD, FL", "Mixed-Use"),
    ("Tallahassee 80-Unit Development", "3-acre parcel", "Tallahassee, FL", "Multifamily"),
    ("50+ Senior Living Concept", "Tampa regional site", "Tampa Region, FL", "Multifamily"),
    ("Buffington / Dodson Development", "Buffington / Dodson, 4.23 acres", "Atlanta Metro, GA", "Multifamily"),
    ("Cascade Palmetto Flagship Platform", "Cascade Palmetto, 258 acres", "Atlanta Metro, GA", "Multifamily"),
    ("Indian Rocks Beach Luxury Coastal Residences", "370 & 372 12th Ave", "Indian Rocks Beach, FL", "Residential"),
]

PROJECTS = [
    ("Atlanta Multi-Asset Portfolio", "Pre-Development", "Planning", 8180000),
    ("PadSplit Portfolio (4)", "Pre-Development", "Planning", None),
    ("Grove Park Portfolio", "Pre-Development", "Planning", None),
    ("Vine City Portfolio", "Pre-Development", "Planning", None),
    ("CBM Section 8 Portfolio", "Pre-Development", "Planning", None),
    ("Dormplex", "Pre-Development", "Planning", None),
    ("Duplex 839 Commodore", "Pre-Development", "Planning", None),
    ("Duplex 308 Anderson", "Pre-Development", "Planning", None),
    ("Duplex 2035 Lois", "Pre-Development", "Planning", None),
    ("Boarding House 338 Candler", "Pre-Development", "Planning", None),
    ("MLK Workforce Townhome Development", "Pre-Development", "Planning", 12300000),
    ("705 Wilma Street Workforce Housing", "Pre-Development", "Planning", 7100000),
    ("622 W MLK Mixed-Use Workforce Housing", "Pre-Development", "Planning", 14000000),
    ("Genesee Residences", "Pre-Development", "Planning", 14000000),
    ("Sligh Ave Attainable Housing", "Pre-Development", "Planning", 13180000),
    ("370 12th Ave Coastal Residence", "Pre-Development", "Planning", 1715000),
    ("372 12th Ave Coastal Residence", "Pre-Development", "Planning", 1925000),
    ("Earlewood / 301 Sunset Drive Redevelopment", "Due Diligence", "Active", 40000000),
    ("Streams at Earlewood", "Pre-Development", "Planning", 68000000),
    ("Gretna Crossroads Mixed-Use Development", "Pre-Development", "Planning", 10000000),
    ("Pensacola Duplex Development", "Pre-Development", "Planning", 872000),
    ("East Tampa Mixed-Use Affordable Housing", "Pre-Development", "Planning", 12840000),
    ("NEXX Sports & Esports Complex", "Pre-Development", "Planning", 16640000),
    ("Starfleet Sports Complex", "Pre-Development", "Planning", 500000000),
    ("Dr. Walter L. Smith Library Redevelopment", "Pre-Development", "Planning", 1600000),
    ("Tallahassee 80-Unit Development", "Pre-Development", "Planning", None),
    ("50+ Senior Living Concept", "Pre-Development", "Planning", None),
    ("Buffington / Dodson Development", "Pre-Development", "Planning", None),
    ("Cascade Palmetto Flagship Platform", "Pre-Development", "Planning", None),
    ("Indian Rocks Beach Luxury Coastal Residences", "Pre-Development", "Planning", 4663000),
]

VENDORS = [
    ("Licensed General Contractor", "GMP pricing and construction execution", "Needed"),
    ("Civil Engineer", "Site/civil, utilities, stormwater", "Needed"),
    ("Architect", "Design, plans, permit sets", "Needed"),
    ("Surveyor", "Boundary, topo, ALTA surveys", "Needed"),
    ("Environmental Consultant", "Phase I/II, wetlands, asbestos", "Needed"),
    ("Real Estate Broker", "Comps, acquisition, disposition", "Needed"),
    ("Property Management / Leasing", "Stabilization and operations", "Needed"),
    ("STR Operator", "Short-term rental management", "Needed"),
    ("Insurance Broker", "Builder's risk, property, liability", "Needed"),
    ("Legal Counsel", "LOI, PSA, JV, zoning, incentives", "Needed"),
]

MILESTONE_PHASES = [
    ("Intake / Site Control", "Pre-Development", 30),
    ("Due Diligence / Validation", "Pre-Development", 90),
    ("Capital Stack / Incentives", "Finance", 180),
    ("Design / Permitting", "Design", 365),
    ("Execution / Construction", "Construction", 730),
    ("Stabilization / Exit", "Closeout", 1095),
]


def get_or_create_portfolio(session):
    """Get existing portfolio or create a new one for admin user."""
    portfolio = session.query(Portfolio).first()
    if portfolio:
        return portfolio
    from app.models import User
    admin = session.query(User).filter_by(username="admin").first()
    if not admin:
        raise RuntimeError("Admin user not found. Run flask db upgrade and flask seed first.")
    portfolio = Portfolio(user_id=admin.id, name="CapitalOps Portfolio", description="Primary real estate development portfolio")
    session.add(portfolio)
    session.flush()
    return portfolio


def seed_assets(session, portfolio, dry_run=False):
    """Create assets. Idempotent: skips assets that already exist by name."""
    print("Seeding assets...")
    for name, location, address, asset_type in ASSETS:
        existing = session.query(Asset).filter_by(name=name).first()
        if existing:
            print(f"  SKIP  (exists): {name}")
            continue
        asset = Asset(
            portfolio_id=portfolio.id,
            name=name,
            location=f"{address} — {location}",
            asset_type=asset_type,
            square_footage=0,
            status="Pre-dev",
        )
        if not dry_run:
            session.add(asset)
        print(f"  CREATE: {name}")


def seed_projects(session, portfolio, dry_run=False):
    """Create projects. Idempotent: skips projects that already exist by linked asset."""
    print("Seeding projects...")
    for asset_name, phase, status, budget_total in PROJECTS:
        asset = session.query(Asset).filter_by(name=asset_name).first()
        if not asset:
            print(f"  SKIP  (asset not found): {asset_name}")
            continue
        existing = session.query(Project).filter_by(asset_id=asset.id).first()
        if existing:
            print(f"  SKIP  (exists): project for {asset_name}")
            continue
        project = Project(
            asset_id=asset.id,
            portfolio_id=portfolio.id,
            phase=phase,
            status=status,
            budget_total=budget_total or 0,
            budget_actual=0,
            pm_assigned="Russell Spears",
        )
        if not dry_run:
            session.add(project)
        print(f"  CREATE: project for {asset_name}")


def seed_vendors(session, portfolio, dry_run=False):
    """Create vendor categories. Idempotent: skips vendors that already exist by name."""
    print("Seeding vendors...")
    for name, description, coi_status in VENDORS:
        existing = session.query(Vendor).filter_by(name=name).first()
        if existing:
            print(f"  SKIP  (exists): {name}")
            continue
        vendor = Vendor(
            name=name,
            type=description,
            coi_status=coi_status,
            sla_type="Standard",
            performance_score=0,
            asset_id=0,
            portfolio_id=portfolio.id,
        )
        if not dry_run:
            session.add(vendor)
        print(f"  CREATE: {name}")


def seed_milestones(session, portfolio, dry_run=False):
    """Create standard milestones for each project. Idempotent per project."""
    print("Seeding milestones...")
    today = date.today()
    for asset_name, phase, status, budget_total in PROJECTS:
        asset = session.query(Asset).filter_by(name=asset_name).first()
        if not asset:
            continue
        project = session.query(Project).filter_by(asset_id=asset.id).first()
        if not project:
            continue
        has_milestones = session.query(Milestone).filter_by(project_id=project.id).first()
        if has_milestones:
            print(f"  SKIP  (milestones exist): {asset_name}")
            continue
        for name, category, days_out in MILESTONE_PHASES:
            milestone = Milestone(
                project_id=project.id,
                portfolio_id=portfolio.id,
                name=name,
                category=category,
                target_date=today + timedelta(days=days_out),
                status="Not Started",
                risk_flag=False,
            )
            if not dry_run:
                session.add(milestone)
        print(f"  CREATE: 6 milestones for {asset_name}")


def run(dry_run=False):
    app = create_app()
    with app.app_context():
        portfolio = get_or_create_portfolio(db.session)
        if dry_run:
            print("=== DRY RUN — no records will be written ===\n")

        seed_assets(db.session, portfolio, dry_run)
        if not dry_run:
            db.session.commit()
            print(f"  Committed {len(ASSETS)} assets\n")

        seed_projects(db.session, portfolio, dry_run)
        if not dry_run:
            db.session.commit()
            print(f"  Committed {len(PROJECTS)} projects\n")

        seed_vendors(db.session, portfolio, dry_run)
        if not dry_run:
            db.session.commit()
            print(f"  Committed {len(VENDORS)} vendors\n")

        seed_milestones(db.session, portfolio, dry_run)
        if not dry_run:
            db.session.commit()
            print(f"  Committed milestones\n")

        if dry_run:
            print("=== DRY RUN COMPLETE ===")
        else:
            print("Seeding complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed demo project data into CapitalOps database.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be created without writing to the database",
    )
    args = parser.parse_args()
    run(dry_run=args.dry_run)
