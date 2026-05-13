"""
CapitalOps API - Entitlement & Notification Routes

Handles permits, entitlements, and system notifications for projects.

Access Control:
    sponsor_admin:
        Full read and write access to all entitlement records and events.

    project_manager:
        Can create/update entitlement records and add events.
        Cannot delete.

Routes:
    GET    /api/v1/entitlement/                        — List all entitlement records
    GET    /api/v1/entitlement/:id                     — Single entitlement record with events
    POST   /api/v1/entitlement/                       — Create entitlement record
    PATCH  /api/v1/entitlement/:id                    — Update entitlement record
    POST   /api/v1/entitlement/:id/events             — Add permit event
    GET    /api/v1/entitlement/notifications           — Unread notifications for current user
    PATCH  /api/v1/entitlement/notifications/:id/read — Mark notification as read
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from app import db
from app.models import EntitlementRecord, PermitEvent, Notification, User
from app.auth_utils import role_required
from app.notifications import create_notification

entitlement_bp = Blueprint("entitlement", __name__)

ENTITLEMENT_ROLES = ("sponsor_admin", "project_manager")


@entitlement_bp.route("/", methods=["GET"])
@jwt_required()
@role_required(*ENTITLEMENT_ROLES)
def index():
    """
    List all entitlement records.

    Query Parameters:
        project_id: Filter by project (optional)
        status: Filter by status (optional)

    Returns (200):
        { "entitlement_records": [ ... ] }
    """
    query = EntitlementRecord.query

    project_id = request.args.get("project_id", type=int)
    if project_id:
        query = query.filter_by(project_id=project_id)

    status = request.args.get("status")
    if status:
        query = query.filter_by(status=status)

    records = query.order_by(EntitlementRecord.created_at.desc()).all()
    return jsonify({
        "entitlement_records": [
            {
                **r.to_dict(),
                "project_name": r.project.name if r.project else None
            }
            for r in records
        ]
    })


@entitlement_bp.route("/<int:entitlement_record_id>", methods=["GET"])
@jwt_required()
@role_required(*ENTITLEMENT_ROLES)
def get_entitlement(entitlement_record_id):
    """
    Get a single entitlement record with all its permit events.

    Returns (200):
        {
            "entitlement_record": { ... },
            "events": [ ... ]  — ordered by detected_at desc
        }

    Returns (404):
        If entitlement_record_id not found
    """
    record = EntitlementRecord.query.get_or_404(entitlement_record_id)
    events = PermitEvent.query.filter_by(
        entitlement_record_id=entitlement_record_id
    ).order_by(PermitEvent.detected_at.desc()).all()

    return jsonify({
        "entitlement_record": {
            **record.to_dict(),
            "project_name": record.project.name if record.project else None
        },
        "events": [e.to_dict() for e in events]
    })


@entitlement_bp.route("/", methods=["POST"])
@jwt_required()
@role_required(*ENTITLEMENT_ROLES)
def create_entitlement():
    """
    Create a new entitlement record.

    Request Body:
        {
            "project_id": int,              — required
            "parcel_number": str,             — required
            "agency": str,                   — required
            "entitlement_type": str,          — required (e.g., "rezoning", "variance", "site plan")
            "status": str,                   — required
            "application_number": str,       — optional
            "submitted_date": "YYYY-MM-DD",   — optional, defaults to today
            "hearing_date": "YYYY-MM-DD",     — optional
            "notes": str,                     — optional
            "source_url": str                 — optional
        }

    Returns (201):
        { "entitlement_record": { ... } }

    Returns (400):
        If required fields are missing
    """
    data = request.get_json() or {}

    required = ["project_id", "parcel_number", "agency", "entitlement_type", "status"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    from datetime import datetime

    record = EntitlementRecord(
        project_id=data["project_id"],
        parcel_number=data["parcel_number"],
        agency=data["agency"],
        application_number=data.get("application_number", ""),
        entitlement_type=data["entitlement_type"],
        status=data["status"],
        submitted_date=datetime.strptime(data["submitted_date"], "%Y-%m-%d").date() if data.get("submitted_date") else datetime.utcnow().date(),
        hearing_date=datetime.strptime(data["hearing_date"], "%Y-%m-%d").date() if data.get("hearing_date") else None,
        notes=data.get("notes"),
        source_url=data.get("source_url"),
    )

    db.session.add(record)
    db.session.commit()

    return jsonify({
        "entitlement_record": {
            **record.to_dict(),
            "project_name": record.project.name if record.project else None
        }
    }), 201


@entitlement_bp.route("/<int:entitlement_record_id>", methods=["PATCH"])
@jwt_required()
@role_required(*ENTITLEMENT_ROLES)
def update_entitlement(entitlement_record_id):
    """
    Update an entitlement record.

    When status changes, automatically creates a PermitEvent record.

    Request Body (all optional):
        {
            "status": str,
            "hearing_date": "YYYY-MM-DD",
            "approved_date": "YYYY-MM-DD",
            "notes": str
        }

    Returns (200):
        { "entitlement_record": { ... } }

    Returns (404):
        If entitlement_record_id not found
    """
    record = EntitlementRecord.query.get_or_404(entitlement_record_id)
    data = request.get_json() or {}

    previous_status = record.status

    if "status" in data and data["status"] != record.status:
        record.status = data["status"]
        event = PermitEvent(
            entitlement_record_id=record.id,
            event_type="status_change",
            previous_value=previous_status,
            new_value=data["status"],
            detected_at=db.func.now(),
            source="manual"
        )
        db.session.add(event)

        project = record.project
        if project and project.pm_assigned:
            pm_user = User.query.filter_by(full_name=project.pm_assigned).first()
            if pm_user:
                create_notification(
                    user_id=pm_user.id,
                    notification_type="entitlement_update",
                    title=f"Entitlement Status Changed: {record.entitlement_type}",
                    body=f"The {record.entitlement_type} for {project.name} has changed from '{previous_status}' to '{data['status']}'.",
                    related_entity_type="entitlement_record",
                    related_entity_id=record.id
                )

    if "hearing_date" in data:
        from datetime import datetime
        record.hearing_date = datetime.strptime(data["hearing_date"], "%Y-%m-%d").date() if data["hearing_date"] else None

    if "approved_date" in data:
        from datetime import datetime
        record.approved_date = datetime.strptime(data["approved_date"], "%Y-%m-%d").date() if data["approved_date"] else None

    if "notes" in data:
        record.notes = data["notes"]

    db.session.commit()

    return jsonify({
        "entitlement_record": {
            **record.to_dict(),
            "project_name": record.project.name if record.project else None
        }
    })


@entitlement_bp.route("/<int:entitlement_record_id>/events", methods=["POST"])
@jwt_required()
@role_required(*ENTITLEMENT_ROLES)
def add_event(entitlement_record_id):
    """
    Manually add a permit event to an entitlement record.

    Request Body:
        {
            "event_type": str,      — required (e.g., "hearing_scheduled", "approved", "denied")
            "new_value": str,        — optional
            "notes": str             — optional (stored as new_value if event_type indicates a value change)
        }

    Returns (201):
        { "event": { ... } }

    Returns (404):
        If entitlement_record_id not found
    """
    record = EntitlementRecord.query.get_or_404(entitlement_record_id)
    data = request.get_json() or {}

    if not data.get("event_type"):
        return jsonify({"error": "event_type is required"}), 400

    event = PermitEvent(
        entitlement_record_id=record.id,
        event_type=data["event_type"],
        previous_value=None,
        new_value=data.get("new_value"),
        detected_at=db.func.now(),
        source="manual"
    )

    db.session.add(event)
    db.session.commit()

    return jsonify({"event": event.to_dict()}), 201


@entitlement_bp.route("/notifications", methods=["GET"])
@jwt_required()
def get_notifications():
    """
    Get all unread notifications for the current authenticated user.

    Returns (200):
        { "notifications": [ ... ] }
    """
    claims = get_jwt()
    user_id = claims.get("sub")

    notifications = Notification.query.filter_by(
        user_id=user_id,
        is_read=False
    ).order_by(Notification.created_at.desc()).all()

    return jsonify({"notifications": [n.to_dict() for n in notifications]})


@entitlement_bp.route("/notifications/<int:notification_id>/read", methods=["PATCH"])
@jwt_required()
def mark_notification_read(notification_id):
    """
    Mark a single notification as read.

    Returns (200):
        { "notification": { ... } }

    Returns (404):
        If notification_id not found or belongs to another user
    """
    claims = get_jwt()
    user_id = claims.get("sub")

    notification = Notification.query.filter_by(
        id=notification_id,
        user_id=user_id
    ).first_or_404()

    notification.is_read = True
    db.session.commit()

    return jsonify({"notification": notification.to_dict()})


@entitlement_bp.route("/poll/trigger", methods=["POST"])
@jwt_required()
@role_required("sponsor_admin")
def trigger_poll():
    """
    Manually trigger the entitlement polling job in a background thread.

    This endpoint is for admin/testing use. The actual automated polling
    runs on a schedule via APScheduler.

    Returns (202):
        { "status": "poll triggered" }
    """
    import threading

    def run_poll():
        from app.services.entitlement_poller import poll_all_entitlements
        from flask import current_app
        app = current_app._get_current_object()
        with app.app_context():
            poll_all_entitlements()

    thread = threading.Thread(target=run_poll, daemon=True)
    thread.start()

    return jsonify({"status": "poll triggered"}), 202