"""
Dev utilities - API routes for development and debugging.

WARNING: These routes should NEVER be exposed in production.
They are intentionally insecure for dev purposes only.

Routes:
    POST /api/v1/dev/seed    - Force re-seed demo data (bypasses normal guard)
    GET  /api/v1/dev/status  - Quick status check
"""

import os
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from app import db
from app.auth_utils import get_current_user, role_required

dev_bp = Blueprint("dev", __name__)


@dev_bp.route("/status", methods=["GET"])
@jwt_required()
@role_required("sponsor_admin")
def status():
    """Quick status check for dev purposes."""
    from app.models import User, Portfolio, Asset
    return jsonify({
        "users": User.query.count(),
        "portfolios": Portfolio.query.count(),
        "assets": Asset.query.count(),
    })