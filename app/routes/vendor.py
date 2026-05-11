"""
CapitalOps API - Module 3: Asset & Vendor Control Routes

Handles vendor management, work order tracking, and operational discipline
for the Asset & Vendor Control module. This module maintains the roster of
approved vendors, tracks work orders and their costs, and monitors vendor
compliance (specifically Certificate of Insurance expiry).

This module enables:
    - Sponsors to register vendors and create/update work orders
    - General contractors to view vendors and manage work orders
    - Vendors to view their own assigned work orders (future scoping)
    - Compliance tracking for COIs (Certificates of Insurance)

Access Control:
    sponsor_admin:
        Full CRUD access: register vendors, create/update work orders.

    general_contractor:
        Read access to vendor directory, create and update work orders.
        Cannot register new vendors (vendors are sponsor-only).

    vendor (future):
        Read access to own work orders only. Not yet fully implemented.

Routes:
    GET   /api/v1/vendor/               — Vendor overview with computed stats
    POST  /api/v1/vendor/               — Register a new vendor (admin only)
    GET   /api/v1/vendor/work-orders    — List all work orders
    POST  /api/v1/vendor/work-orders   — Create a new work order
    PATCH /api/v1/vendor/work-orders/<id> — Update work order status/cost

Security Considerations:
    - JWT required for all endpoints
    - Role-based access via @role_required decorator
    - sponsor_admin-only endpoints prevent unauthorized vendor registration
    - general_contractor can create work orders but cannot register vendors
    - Work order status transitions should be validated (e.g., can't go from
      Open to Complete without actual completion, but this is not enforced)
    - No financial fields are redacted — ensure role-based field hiding is
      reviewed if sensitive cost data is added to the response
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from app import db
from app.models import Vendor, WorkOrder, Asset, Portfolio, FieldMedia
from app.auth_utils import role_required
import boto3
import botocore.exceptions
import uuid
import os

vendor_bp = Blueprint("vendor", __name__)

# Roles permitted to access Asset & Vendor Control routes.
# sponsor_admin: full access
# general_contractor: view vendors, create/update work orders
# vendor: view own work orders (future — not yet enforced at query level)
VENDOR_ROLES = ("sponsor_admin", "general_contractor", "vendor")


@vendor_bp.route("/", methods=["GET"])
@jwt_required()
@role_required(*VENDOR_ROLES)
def index():
    """
    Vendor & Asset Control overview with computed summary statistics.

    Returns the complete vendor roster, work order list, and asset list
    along with pre-computed metrics for the vendor management dashboard.

    Summary Statistics computed:
        - total_vendors: Total vendor count
        - coi_expired: Vendors with coi_status="Expired"
          (expired insurance is a compliance risk requiring attention)
        - open_orders: Work orders not in "Complete" or "Cancelled" status
        - total_cost: Sum of all work order costs
        - capex_total: Sum of work order costs where capex_flag=True
          (capital expenditures vs operating expenses)
        - opex_total: total_cost - capex_total
          (operating expenditures distinction)

    Data returned:
        - Full Vendor objects (via .to_dict())
        - Full WorkOrder objects sorted by created_at desc
        - Full Asset objects (via .to_dict())

    Returns (200):
        {
            "stats": {
                "total_vendors": number,
                "coi_expired": number,
                "open_orders": number,
                "total_cost": number,
                "capex_total": number,
                "opex_total": number
            },
            "vendors": [...],
            "work_orders": [...],
            "assets": [...]
        }
    """
    vendors = Vendor.query.all()
    # Work orders sorted by most recent first for dashboard display
    work_orders = WorkOrder.query.order_by(WorkOrder.created_at.desc()).all()
    assets = Asset.query.all()

    # Compute summary statistics
    # COI = Certificate of Insurance — expired COIs are a compliance risk
    coi_expired = sum(1 for v in vendors if v.coi_status == "Expired")
    # Open orders = anything not finalized (complete or cancelled)
    open_orders = sum(1 for wo in work_orders if wo.status not in ("Complete", "Cancelled"))
    # Total cost across all work orders
    total_cost = sum(float(wo.cost or 0) for wo in work_orders)
    # Capex vs Opex split — capex_flag marks capital expenditures
    capex_total = sum(float(wo.cost or 0) for wo in work_orders if wo.capex_flag)
    opex_total = total_cost - capex_total

    stats = {
        "total_vendors": len(vendors),
        "coi_expired": coi_expired,
        "open_orders": open_orders,
        "total_cost": total_cost,
        "capex_total": capex_total,
        "opex_total": opex_total,
    }

    return jsonify({
        "stats": stats,
        "vendors": [v.to_dict() for v in vendors],
        "work_orders": [wo.to_dict() for wo in work_orders],
        "assets": [a.to_dict() for a in assets],
    })


@vendor_bp.route("/", methods=["POST"])
@jwt_required()
@role_required("sponsor_admin")
def create_vendor():
    """
    Register a new vendor for an asset.

    Restricted to sponsor_admin role. This ensures only authorized
    personnel can add vendors to the approved roster.

    The vendor is automatically associated with the first Portfolio in
    the system. This default behavior should be reviewed if multi-portfolio
    support is added later (vendors should be explicitly assigned to a
    portfolio rather than auto-assigned).

    Request Format:
        Content-Type: application/json
        Body: {
            "asset_id": 123,              (required)
            "name": "ABC Electrical LLC", (required)
            "type": "Electrical",         (optional, default: "")
            "coi_status": "Valid",        (optional, default: "Pending")
            "sla_type": "Standard",       (optional, default: "Standard")
            "performance_score": 85       (optional, default: 0)
        }

    Returns (201):
        { "vendor": { ... created vendor object ... } }

    Returns (400):
        { "error": "asset_id and name are required" }
        if either required field is missing
    """
    data = request.get_json()
    if not data or not data.get("asset_id") or not data.get("name"):
        return jsonify({"error": "asset_id and name are required"}), 400

    # Auto-assign to the current portfolio.
    # If no portfolio exists, this will fail (Portfolio.query.first() returns None).
    # In a multi-portfolio system, the portfolio_id should be explicitly passed.
    portfolio = Portfolio.query.first()

    vendor = Vendor(
        asset_id=data["asset_id"],
        portfolio_id=portfolio.id,
        name=data["name"],
        type=data.get("type", ""),
        coi_status=data.get("coi_status", "Pending"),
        sla_type=data.get("sla_type", "Standard"),
        performance_score=data.get("performance_score", 0),
    )
    db.session.add(vendor)
    db.session.commit()

    return jsonify({"vendor": vendor.to_dict()}), 201


@vendor_bp.route("/work-orders", methods=["GET"])
@jwt_required()
@role_required(*VENDOR_ROLES)
def list_work_orders():
    """
    List all work orders, sorted by most recent first.

    Returns the complete work order list for vendor management and
    oversight. Work orders are sorted by created_at descending so
    the most recent orders appear first in the UI.

    Returns (200):
        { "work_orders": [...] }
    """
    work_orders = WorkOrder.query.order_by(WorkOrder.created_at.desc()).all()
    return jsonify({"work_orders": [wo.to_dict() for wo in work_orders]})


@vendor_bp.route("/work-orders", methods=["POST"])
@jwt_required()
@role_required("sponsor_admin", "general_contractor")
def create_work_order():
    """
    Create a new work order for a vendor and asset.

    Work orders represent specific tasks or services assigned to a vendor
    for a particular asset. They track priority, estimated cost, and
    whether the cost should be classified as capital expenditure (CAPEX)
    or operating expenditure (OPEX).

    Role restrictions:
        - sponsor_admin: Full create access
        - general_contractor: Can create work orders (reflects real-world
          where contractors initiate work requests that then need sponsor approval)

    Request Format:
        Content-Type: application/json
        Body: {
            "vendor_id": 123,            (required)
            "asset_id": 456,             (required)
            "type": "HVAC Repair",        (optional, default: "")
            "priority": "High",           (optional, default: "Normal")
            "cost": 15000.00,             (optional, default: 0)
            "capex_flag": false           (optional, default: false)
                                         — true = capital expenditure
                                         — false = operating expense
        }

    Returns (201):
        { "work_order": { ... created work order object ... } }

    Returns (400):
        { "error": "vendor_id and asset_id are required" }
        if either required field is missing
    """
    data = request.get_json()
    if not data or not data.get("vendor_id") or not data.get("asset_id"):
        return jsonify({"error": "vendor_id and asset_id are required"}), 400

    # Auto-assign to the first portfolio (same pattern as create_vendor)
    portfolio = Portfolio.query.first()

    wo = WorkOrder(
        vendor_id=data["vendor_id"],
        asset_id=data["asset_id"],
        portfolio_id=portfolio.id,
        type=data.get("type", ""),
        priority=data.get("priority", "Normal"),
        cost=data.get("cost", 0),
        capex_flag=data.get("capex_flag", False),
        status="Open",
    )
    db.session.add(wo)
    db.session.commit()

    return jsonify({"work_order": wo.to_dict()}), 201


@vendor_bp.route("/work-orders/<int:wo_id>", methods=["PATCH"])
@jwt_required()
@role_required(*VENDOR_ROLES)
def update_work_order(wo_id):
    """
    Update a work order's status and/or cost.

    This is the primary endpoint for managing work order lifecycle.
    It supports two field updates:
        - status: Work order state (e.g., "Open" → "In Progress" → "Complete")
        - cost: Actual or revised cost for the work order

    All roles in VENDOR_ROLES can update work orders. In a more granular
    system, vendors would only be able to update work orders assigned
    to them (vendor_id check), but that enforcement is not yet implemented.

    URL Parameters:
        wo_id: Integer primary key of the WorkOrder

    Request Format:
        Content-Type: application/json
        Body (both fields optional):
        {
            "status": "Complete",     — New status value
            "cost": 17500.00          — Updated/revised cost
        }

    Returns (200):
        { "work_order": { ... updated work order object ... } }

    Returns (404):
        If wo_id does not correspond to an existing WorkOrder
    """
    wo = WorkOrder.query.get_or_404(wo_id)
    data = request.get_json() or {}

    if "status" in data:
        wo.status = data["status"]
    if "cost" in data:
        wo.cost = data["cost"]

    db.session.commit()
    return jsonify({"work_order": wo.to_dict()})


@vendor_bp.route("/media/presign", methods=["POST"])
@jwt_required()
def presign_media():
    """
    Generate a presigned S3 PUT URL for direct media upload.

    The client uploads directly to S3 using the presigned URL, then
    calls POST /media to create the FieldMedia record.

    Request Body:
        {
            "filename": str,           — required
            "media_type": str,         — required ("photo" or "video")
            "project_id": int,         — optional
            "work_order_id": int       — optional
        }

    Returns (400):
        If project_id and work_order_id are both missing
        If media_type is not "photo" or "video"

    Returns (200):
        {
            "presigned_url": str,
            "s3_key": str,
            "s3_bucket": str,
            "expires_in": int
        }
    """
    data = request.get_json() or {}

    filename = data.get("filename")
    media_type = data.get("media_type")
    project_id = data.get("project_id")
    work_order_id = data.get("work_order_id")

    if not filename or not media_type:
        return jsonify({"error": "filename and media_type are required"}), 400

    if media_type not in ("photo", "video"):
        return jsonify({"error": "media_type must be 'photo' or 'video'"}), 400

    if not project_id and not work_order_id:
        return jsonify({"error": "at least one of project_id or work_order_id is required"}), 400

    bucket = os.environ.get("AWS_BUCKET_NAME")
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_REGION", "us-east-1")

    if not bucket or not access_key or not secret_key:
        return jsonify({"error": "S3 not configured"}), 500

    entity_id = project_id or work_order_id
    s3_key = f"field-media/{entity_id}/{uuid.uuid4()}/{filename}"

    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        presigned_url = s3.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": bucket,
                "Key": s3_key,
                "ContentType": "application/octet-stream"
            },
            ExpiresIn=3600
        )
        return jsonify({
            "presigned_url": presigned_url,
            "s3_key": s3_key,
            "s3_bucket": bucket,
            "expires_in": 3600
        })
    except botocore.exceptions.ClientError as e:
        return jsonify({"error": str(e)}), 500


@vendor_bp.route("/media", methods=["POST"])
@jwt_required()
def create_media_record():
    """
    Create a FieldMedia record after client uploads to S3.

    Request Body:
        {
            "s3_key": str,             — required
            "s3_bucket": str,           — required
            "filename": str,            — required
            "media_type": str,          — required ("photo" or "video")
            "project_id": int,          — optional
            "work_order_id": int        — optional
            "caption": str              — optional
        }

    Returns (201):
        { "field_media": { ... } }
    """
    data = request.get_json() or {}
    claims = get_jwt()
    user_id = claims.get("sub")

    required = ["s3_key", "s3_bucket", "filename", "media_type"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    if data["media_type"] not in ("photo", "video"):
        return jsonify({"error": "media_type must be 'photo' or 'video'"}), 400

    if not data.get("project_id") and not data.get("work_order_id"):
        return jsonify({"error": "at least one of project_id or work_order_id is required"}), 400

    media = FieldMedia(
        project_id=data.get("project_id"),
        work_order_id=data.get("work_order_id"),
        uploaded_by_user_id=user_id,
        media_type=data["media_type"],
        s3_key=data["s3_key"],
        s3_bucket=data["s3_bucket"],
        filename=data["filename"],
        caption=data.get("caption"),
    )

    db.session.add(media)
    db.session.commit()

    return jsonify({"field_media": media.to_dict()}), 201


@vendor_bp.route("/media", methods=["GET"])
@jwt_required()
def list_media():
    """
    List FieldMedia records with presigned GET URLs.

    Query Parameters:
        project_id: Filter by project (optional)
        work_order_id: Filter by work order (optional)

    Presigned URLs expire after 1 hour.

    Returns (200):
        { "field_media": [ ... ] }
    """
    query = FieldMedia.query

    project_id = request.args.get("project_id", type=int)
    if project_id:
        query = query.filter_by(project_id=project_id)

    work_order_id = request.args.get("work_order_id", type=int)
    if work_order_id:
        query = query.filter_by(work_order_id=work_order_id)

    records = query.order_by(FieldMedia.uploaded_at.desc()).all()

    bucket = os.environ.get("AWS_BUCKET_NAME")
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_REGION", "us-east-1")

    media_list = []
    for record in records:
        record_dict = record.to_dict()
        if bucket and access_key and secret_key:
            try:
                s3 = boto3.client(
                    "s3",
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region,
                )
                presigned_get_url = s3.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": record.s3_bucket, "Key": record.s3_key},
                    ExpiresIn=3600
                )
                record_dict["presigned_url"] = presigned_get_url
            except botocore.exceptions.ClientError:
                record_dict["presigned_url"] = None
        else:
            record_dict["presigned_url"] = None
        media_list.append(record_dict)

    return jsonify({"field_media": media_list})


@vendor_bp.route("/media/<int:media_id>", methods=["DELETE"])
@jwt_required()
def delete_media(media_id):
    """
    Delete a FieldMedia record and its S3 object.

    Restricted to the uploader (uploaded_by_user_id matches current user)
    or sponsor_admin role.

    Returns (204):
        No content on success

    Returns (403):
        If user is not the uploader and not sponsor_admin

    Returns (404):
        If media_id not found
    """
    media = FieldMedia.query.get_or_404(media_id)
    claims = get_jwt()
    user_id = claims.get("sub")
    user_role = claims.get("role", "")

    if media.uploaded_by_user_id != int(user_id) and user_role != "sponsor_admin":
        return jsonify({"error": "Not authorized to delete this media"}), 403

    bucket = os.environ.get("AWS_BUCKET_NAME")
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_REGION", "us-east-1")

    if bucket and access_key and secret_key:
        try:
            s3 = boto3.client(
                "s3",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
            s3.delete_object(Bucket=media.s3_bucket, Key=media.s3_key)
        except botocore.exceptions.ClientError:
            pass

    db.session.delete(media)
    db.session.commit()

    return "", 204
