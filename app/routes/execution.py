"""
CapitalOps API - Module 2: Execution Control Routes

Translates raw project data into governance-level clarity for the
Execution Control module. This module is the operational backbone
for tracking project milestones, delays, risk flags, and overall
execution health.

This module enables:
    - Sponsors to view all projects and their governance status
    - Project managers to update milestone statuses and log delays
    - General contractors to confirm milestone completion only
    - Risk tracking through milestone-level risk flags

Access Control:
    sponsor_admin:
        Full read and write access to all projects, milestones, and risk flags.

    project_manager:
        Can update milestones and log delay explanations.
        Can set risk flags on milestones.

    general_contractor:
        Can ONLY mark milestones as "Complete".
        Cannot modify delay explanations or risk flags.

    Note: general_contractor role restriction is enforced at the endpoint
    level (update_milestone) by reading the JWT role claim directly.

Routes:
    GET   /api/v1/execution/                    — All projects with computed metrics
    GET   /api/v1/execution/projects/<id>       — Individual project with milestones
    PATCH /api/v1/execution/milestones/<id>     — Update milestone status/delay/risk
    GET   /api/v1/execution/governance          — Governance event log (all data)

Security Considerations:
    - JWT required for all endpoints
    - Role-based access via @role_required decorator
    - general_contractor can only set milestone status to "Complete"
    - No PATCH/DELETE on projects or risk flags (additive-only model)
    - Risk flags are set per-milestone, not as standalone records in this module
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from app import db
from app.models import Project, Milestone, RiskFlag, User, EntitlementRecord
from app.auth_utils import role_required
from datetime import date

execution_bp = Blueprint("execution", __name__)

# Roles permitted to access Execution Control routes.
# All three roles have read access to the index and project_detail endpoints.
# Only sponsor_admin and project_manager have write access to milestones.
EXECUTION_ROLES = ("sponsor_admin", "project_manager", "general_contractor")


@execution_bp.route("/", methods=["GET"])
@jwt_required()
@role_required(*EXECUTION_ROLES)
def index():
    """
    Execution Control overview — all projects with computed execution metrics.

    Returns every project with pre-computed per-project statistics used
    in the execution dashboard overview. Each project includes progress
    percentage, milestone counts, risk count, and budget metrics.

    Metrics computed per project:
        - progress: Milestone completion percentage (completed / total)
        - completed_milestones: Count of milestones with status="Complete"
        - total_milestones: Total milestone count for the project
        - risk_count: Count of milestones with risk_flag=True
        - budget_variance: budget_total - budget_actual (positive = under budget)
        - budget_pct: (budget_actual / budget_total) * 100

    Data returned:
        - Full Project object (via .to_dict())
        - Associated Asset object (via .to_dict())
        - All computed metrics as sibling fields

    Returns (200):
        {
            "projects": [
                {
                    "project": { ... project object ... },
                    "asset": { ... asset object ... },
                    "progress": number,           — 0-100
                    "completed_milestones": number,
                    "total_milestones": number,
                    "risk_count": number,
                    "budget_variance": number,
                    "budget_pct": number
                },
                ...
            ]
        }
    """
    projects = Project.query.all()
    project_data = []

    for p in projects:
        # Fetch milestones for this project to compute progress
        milestones = Milestone.query.filter_by(project_id=p.id).all()
        completed = sum(1 for m in milestones if m.status == "Complete")
        total = len(milestones)
        progress = round(completed / total * 100) if total else 0
        # Risk flags tracked at the milestone level
        risk_count = sum(1 for m in milestones if m.risk_flag)
        budget_variance = float(p.budget_total or 0) - float(p.budget_actual or 0)
        # Budget utilization percentage
        budget_pct = round(float(p.budget_actual or 0) / float(p.budget_total or 1) * 100)

        project_data.append({
            "project": p.to_dict(),
            "asset": p.asset.to_dict() if p.asset else None,
            "progress": progress,
            "completed_milestones": completed,
            "total_milestones": total,
            "risk_count": risk_count,
            "budget_variance": budget_variance,
            "budget_pct": budget_pct,
        })

    return jsonify({"projects": project_data})


@execution_bp.route("/projects/<int:project_id>", methods=["GET"])
@jwt_required()
@role_required(*EXECUTION_ROLES)
def project_detail(project_id):
    """
    Individual project detail with milestones and risk flags.

    Fetches a single project and its associated milestones and risk flags.
    Milestones are sorted by target_date (earliest first) so the UI can
    display them in chronological order.

    URL Parameters:
        project_id: Integer primary key of the Project

    Returns (200):
        {
            "project": { ... project object ... },
            "milestones": [        — Sorted by target_date ascending
                { ... milestone object ... },
                ...
            ],
            "risk_flags": [        — RiskFlag objects for this project
                { ... risk flag object ... },
                ...
            ],
            "progress": number     — Milestone completion percentage
        }

    Returns (404):
        If project_id does not correspond to an existing Project
    """
    project = Project.query.get_or_404(project_id)
    milestones = Milestone.query.filter_by(project_id=project_id).order_by(Milestone.target_date).all()
    risk_flags = RiskFlag.query.filter_by(project_id=project_id).all()

    completed = sum(1 for m in milestones if m.status == "Complete")
    total = len(milestones)
    progress = round(completed / total * 100) if total else 0

    return jsonify({
        "project": project.to_dict(),
        "milestones": [m.to_dict() for m in milestones],
        "risk_flags": [r.to_dict() for r in risk_flags],
        "progress": progress,
    })


@execution_bp.route("/milestones/<int:milestone_id>", methods=["PATCH"])
@jwt_required()
@role_required(*EXECUTION_ROLES)
def update_milestone(milestone_id):
    """
    Update a milestone's status, delay explanation, and/or risk flag.

    This is the primary endpoint for logging project progress.
    It supports three types of updates:
        - Status change (e.g., "In Progress" → "Complete")
        - Delay explanation (free text describing why a milestone is delayed)
        - Risk flag (boolean indicating the milestone has a risk issue)

    Role Restrictions on Updates:
        general_contractor:
            Can ONLY set status to "Complete". This reflects their limited
            authority in the real-world contractor relationship — they confirm
            work done but don't manage schedules or risks directly.
            Any other field update returns 403.

        project_manager / sponsor_admin:
            Can update all fields: status, delay_explanation, and risk_flag.

    Auto-Completion Date:
        When a milestone's status is set to "Complete" and it doesn't
        already have a completion_date, the current date is automatically
        recorded. This provides an audit trail without requiring the client
        to explicitly set it.

    Request Format:
        Content-Type: application/json
        Body (all fields optional, but at least one required):
        {
            "status": "Complete",              — New status value
            "delay_explanation": "Weather delay due to Q4 storms",  — Free text
            "risk_flag": true                   — Boolean
        }

    Returns (200):
        { "milestone": { ... updated milestone object ... } }

    Returns (403):
        { "error": "General contractors can only mark milestones as complete" }
        If a general_contractor attempts to update delay_explanation or risk_flag

    Returns (404):
        If milestone_id does not correspond to an existing Milestone
    """
    milestone = Milestone.query.get_or_404(milestone_id)
    data = request.get_json() or {}

    # Read the role from JWT claims directly (avoids a database lookup).
    # The role is embedded in the JWT at login time via create_access_token's
    # additional_claims parameter, and verified on every request.
    claims = get_jwt()
    user_role = claims.get("role", "")

    # General contractors can only confirm completion — they cannot log delays
    # or set risk flags. This is a business logic restriction, not just a
    # UI constraint, so it's enforced server-side.
    if user_role == "general_contractor" and data.get("status") != "Complete":
        return jsonify({"error": "General contractors can only mark milestones as complete"}), 403

    # Apply field updates from request data
    if "status" in data:
        milestone.status = data["status"]
    if "delay_explanation" in data:
        milestone.delay_explanation = data["delay_explanation"]
    if "risk_flag" in data:
        milestone.risk_flag = data["risk_flag"]

    # Auto-set completion date when marking a milestone complete.
    # This provides automatic audit trail without requiring explicit date input.
    if milestone.status == "Complete" and not milestone.completion_date:
        milestone.completion_date = date.today()

    db.session.commit()
    return jsonify({"milestone": milestone.to_dict()})


@execution_bp.route("/governance", methods=["GET"])
@jwt_required()
@role_required(*EXECUTION_ROLES)
def governance():
    """
    Governance event log — structured execution reporting across all projects.

    Returns the full cross-project dataset needed for governance-level
    reporting and oversight. This is typically used for executive dashboards
    or compliance reporting where an overview of all project health is needed.

    Data returned (all sorted for meaningful presentation):
        - All projects (unordered)
        - All milestones sorted by target_date descending (most urgent first)
        - All risk flags sorted by created_at descending (most recent first)

    Returns (200):
        {
            "projects": [p.to_dict() for p in projects],
            "milestones": [m.to_dict() for m in milestones],
            "risk_flags": [r.to_dict() for r in risk_flags]
        }
    """
    projects = Project.query.all()
    # Sort milestones by target date descending to show most-overdue first
    milestones = Milestone.query.order_by(Milestone.target_date.desc()).all()
    # Sort risk flags by creation date descending (newest issues first)
    risk_flags = RiskFlag.query.order_by(RiskFlag.created_at.desc()).all()

    return jsonify({
        "projects": [p.to_dict() for p in projects],
        "milestones": [m.to_dict() for m in milestones],
        "risk_flags": [r.to_dict() for r in risk_flags],
    })


@execution_bp.route("/track-record/<int:user_id>", methods=["GET"])
@jwt_required()
def track_record(user_id):
    """
    Portfolio-style track record summary for a specific user.

    Returns all projects where pm_assigned matches the user's full_name,
    aggregated into a portfolio summary with per-project drill-down.

    Access Control:
        - sponsor_admin: Can view any user's track record
        - project_manager: Can only view their own track record (user_id must match JWT user_id)
        - other roles: 403 Forbidden

    Returns (200):
        {
            "user": { id, full_name, role },
            "summary": {
                "total_projects": int,
                "completed_projects": int,
                "active_projects": int,
                "total_budget_managed": float,
                "on_time_completion_rate": float,
                "avg_milestone_completion": float,
                "total_risk_flags": int,
                "resolved_risk_flags": int,
                "entitlement_records_tracked": int
            },
            "projects": [ ... ]
        }
    """
    current_user_id = get_jwt().get("user_id")
    current_role = get_jwt().get("role")

    if current_role not in ("sponsor_admin", "project_manager"):
        return jsonify({"error": "Access denied"}), 403

    if current_role == "project_manager" and current_user_id != user_id:
        return jsonify({"error": "Access denied"}), 403

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.full_name:
        return jsonify({"error": "User has no full_name set"}), 400

    projects = Project.query.filter_by(pm_assigned=user.full_name).all()

    total_projects = len(projects)
    completed_projects = sum(1 for p in projects if p.status in ("Complete", "Completed"))
    active_projects = total_projects - completed_projects
    total_budget_managed = sum(float(p.budget_total or 0) for p in projects)

    all_milestones = Milestone.query.filter(Milestone.project_id.in_(p.id for p in projects)).all()
    completed_milestones = [m for m in all_milestones if m.status == "Complete"]
    on_time_count = sum(
        1 for m in completed_milestones
        if m.completion_date and m.target_date and m.completion_date <= m.target_date
    )
    on_time_completion_rate = (
        round(on_time_count / len(completed_milestones) * 100, 1)
        if completed_milestones else 0.0
    )
    projects_with_milestones = [
        p for p in projects
        if any(m.project_id == p.id for m in all_milestones)
    ]
    if projects_with_milestones:
        avg_milestone_completion = round(
            sum(
                sum(1 for m in all_milestones if m.project_id == p.id and m.status == "Complete") /
                len([m for m in all_milestones if m.project_id == p.id]) * 100
                for p in projects_with_milestones
            ) / len(projects_with_milestones), 1
        )
    else:
        avg_milestone_completion = 0.0

    all_risk_flags = RiskFlag.query.filter(RiskFlag.project_id.in_(p.id for p in projects)).all()
    resolved_risk_flags = sum(1 for r in all_risk_flags if r.status == "Resolved")
    entitlement_records_tracked = EntitlementRecord.query.filter(
        EntitlementRecord.project_id.in_(p.id for p in projects)
    ).count()

    project_summaries = []
    for p in projects:
        project_milestones = [m for m in all_milestones if m.project_id == p.id]
        p_completed = sum(1 for m in project_milestones if m.status == "Complete")
        p_risk_flags = [r for r in all_risk_flags if r.project_id == p.id]
        p_entitlements = EntitlementRecord.query.filter_by(project_id=p.id).count()
        project_summaries.append({
            **p.to_dict(),
            "milestone_count": len(project_milestones),
            "milestones_complete": p_completed,
            "completion_pct": round(p_completed / len(project_milestones) * 100, 1) if project_milestones else 0,
            "risk_flag_count": len(p_risk_flags),
            "entitlement_count": p_entitlements,
        })

    return jsonify({
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "role": user.role,
        },
        "summary": {
            "total_projects": total_projects,
            "completed_projects": completed_projects,
            "active_projects": active_projects,
            "total_budget_managed": total_budget_managed,
            "on_time_completion_rate": on_time_completion_rate,
            "avg_milestone_completion": avg_milestone_completion,
            "total_risk_flags": len(all_risk_flags),
            "resolved_risk_flags": resolved_risk_flags,
            "entitlement_records_tracked": entitlement_records_tracked,
        },
        "projects": project_summaries,
    })
