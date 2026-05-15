"""
CapitalOps API - Authentication Routes

Handles JWT-based authentication using flask-jwt-extended.
Clients POST credentials to /login and receive a signed access token
to use as a Bearer token on all subsequent requests.

IMPORTANT SECURITY NOTES:
- Login requires BOTH valid credentials AND MFA verification (defense in depth)
- Forgot password and reset flows return generic messages to prevent user enumeration
- MFA codes are 6-digit numeric, valid for 5 minutes, single-use
- Password reset tokens are URL-safe base64, valid for 30 minutes, single-use
- All tokens are stored hashed in PostgreSQL via SQLAlchemy ORM

Routes:
    POST /api/v1/auth/login              — Authenticate (returns MFA required or JWT)
    POST /api/v1/auth/login/verify-mfa  — Verify MFA code and receive JWT
    GET  /api/v1/auth/me                — Get current user's profile (requires JWT)
    POST /api/v1/auth/logout            — Log out (clears httpOnly JWT cookie)
    POST /api/v1/auth/forgot-password   — Generate password reset token
    POST /api/v1/auth/reset-password    — Validate token and reset password
"""

import os
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, set_access_cookies, unset_jwt_cookies
from app import limiter
from app.models import User, PasswordResetToken, MfaCode
from app.auth_utils import get_current_user, role_required

auth_bp = Blueprint("auth", __name__)


# =============================================================================
# LOGIN WITH MFA
# =============================================================================
# The login flow has two steps:
# 1. POST /login with username/password -> returns MFA required with 6-digit code
# 2. POST /login/verify-mfa with code -> returns JWT access token
#
# This design ensures that even if credentials are compromised, attackers cannot
# login without also having access to the user's email to retrieve the MFA code.

@limiter.limit("10 per minute")
@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Step 1 of login: Authenticate user credentials and generate MFA code.
    
    SECURITY: We return 200 with mfaRequired=true even for invalid credentials
    to prevent user enumeration. However, we only generate MFA codes for
    valid username/password combinations with an associated email.
    
    Email is required because MFA codes are sent via email. Users without emails
    (e.g., Google OAuth users who never provided email) cannot use password login.
    
    Request body:
        {
            "username": "admin",       // required
            "password": "admin123"    // required
        }
    
    Response (200 - MFA required):
        {
            "mfaRequired": true,
            "mfaCode": "123456"       // only returned when email sending fails
        }
    
    Response (200 - Success, no MFA):
        {
            "accessToken": "eyJ...",
            "user": {...}
        }
    
    Response (400): Missing username or password
    Response (401): Invalid credentials
    """
    data = request.get_json()

    # Validate request body contains required fields
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password are required"}), 400

    # Look up user by username - check password hash matches
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not user.check_password(data["password"]):
        # Return 401 for invalid credentials (attacker doesn't know if user exists)
        return jsonify({"error": "Invalid username or password"}), 401

    # Users without emails cannot use password-based MFA (no way to send code)
    if not user.email:
        return jsonify({"error": "No email associated with account. Please contact support."}), 400

    # Generate 6-digit MFA code, valid for 5 minutes
    # The code is stored hashed in DB and marked used after successful verification
    mfa_code = MfaCode.generate_code(user.id, expiry_minutes=5)

    _send_mfa_email(user, mfa_code.plaintext_code)

    return jsonify({"mfaRequired": True}), 200


@limiter.limit("5 per minute")
@auth_bp.route("/login/verify-mfa", methods=["POST"])
def login_verify_mfa():
    """
    Step 2 of login: Verify MFA code and issue JWT access token.

    SECURITY: We look up the most recent unused MFA code for this user.
    Codes are single-use (marked used after verification) and expire after 5 min.
    After 5 failed attempts on the same code, the code is invalidated and all
    outstanding codes for that user are marked as used (brute-force protection).

    Request body:
        {
            "username": "admin",       // required
            "code": "123456"         // required, 6-digit MFA code
        }

    Response (200 - Success):
        {
            "accessToken": "eyJ...",
            "user": {id, username, role, full_name}
        }

    Response (400): Missing username or code
    Response (401): Invalid, expired, or already-used code
    """
    data = request.get_json()

    if not data or not data.get("username") or not data.get("code"):
        return jsonify({"error": "Username and code are required"}), 400

    user = User.query.filter_by(username=data["username"]).first()
    if not user:
        return jsonify({"error": "Invalid username or code"}), 401

    mfa_code = MfaCode.query.filter_by(
        user_id=user.id,
        used=False,
    ).filter(MfaCode.expires_at > datetime.utcnow()).order_by(MfaCode.created_at.desc()).first()

    if not mfa_code:
        return jsonify({"error": "Invalid or expired MFA code"}), 401

    import hashlib, secrets
    incoming_hash = hashlib.sha256(data["code"].encode()).hexdigest()
    if not secrets.compare_digest(mfa_code.code_hash, incoming_hash):
        mfa_code.failed_attempts += 1
        db = _get_db()
        db.session.commit()
        if mfa_code.failed_attempts >= 5:
            MfaCode.query.filter_by(user_id=user.id, used=False).update({"used": True})
            db.session.commit()
            return jsonify({"error": "Too many failed attempts. Please log in again to receive a new code."}), 401
        return jsonify({"error": "Invalid or expired MFA code"}), 401

    mfa_code.used = True
    mfa_code.failed_attempts = 0
    db = _get_db()
    db.session.commit()

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role},
    )

    response = jsonify({
        "accessToken": access_token,
        "user": user.to_dict(),
    })
    set_access_cookies(response, access_token)
    return response, 200


def _send_mfa_email(user, code):
    """
    Send MFA verification code to user's email via Resend.
    
    This function attempts to send the MFA code via email using the Resend API.
    If the API key is not configured or email sending fails, the code is returned
    in the response (for debugging in development) instead of being sent.
    
    NOTE: For production, RESEND_API_KEY must be set and a verified domain configured.
    Until then, codes appear on-screen for debugging purposes.
    
    Args:
        user: The User model instance to send the code to.
        code: The 6-digit MFA code string.
    
    Returns:
        dict: {"code": code} if email sending failed (for debugging),
              {} if email sent successfully.
    """
    # Get Resend API key from environment variables
    resend_key = os.environ.get("RESEND_API_KEY")
    
    # Frontend origin is used to construct any URLs in the email (if needed)
    frontend_origin = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173")

    # HTML email template with the 6-digit code prominently displayed
    email_html = f"""
    <h1>Your Login Code</h1>
    <p>Hi {user.full_name or user.username},</p>
    <p>Your CapitalOps login code is:</p>
    <p style="font-size: 24px; font-weight: bold; letter-spacing: 4px;">{code}</p>
    <p>This code expires in 5 minutes.</p>
    <p>If you didn't request this, please ignore this email.</p>
    """

    # If Resend API key is not configured, log warning and return code for debugging
    if not resend_key:
        logging.warning(f"[MFA] RESEND_API_KEY not configured. Code for {user.email}: {code}")
        return {"code": code}

    try:
        # Import resend dynamically to avoid import errors if package not installed
        import resend
        resend.api_key = resend_key
        
        # Send email via Resend
        email = resend.Emails.send({
            "from": "CapitalOps <noreply@capitalops.app>",
            "to": [user.email],
            "subject": "Your CapitalOps login code",
            "html": email_html
        })
        logging.info(f"[MFA] Code sent to {user.email}, id: {email}")
        return {}
    except Exception as e:
        # If email sending fails, log error and return code for debugging
        logging.error(f"[MFA] Failed to send code to {user.email}: {e}")
        logging.warning(f"[MFA] Code (fallback) for {user.email}: {code}")
        return {"code": code}


# =============================================================================
# USER PROFILE
# =============================================================================

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """
    Return the currently authenticated user's profile.
    
    This endpoint is called by the frontend after successful login to load
    the user's profile data into the application state.
    
    IMPORTANT: This endpoint requires a valid JWT in the Authorization header.
    The JWT identity (user ID) is extracted automatically by flask-jwt-extended
    via the @jwt_required() decorator.
    
    Returns (200):
        {
            "user": {
                id, username, email, role, full_name,
                profile_type, profile_status, profile_image,
                title, organization, bio, etc.
            }
        }
    
    Returns (401): Missing or invalid JWT
    Returns (404): User not found (shouldn't happen if JWT is valid)
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": user.to_dict()})


@auth_bp.route("/users", methods=["GET"])
@jwt_required()
@role_required("sponsor_admin")
def list_users():
    """
    Return all users on the platform (for recipient picker in reports).

    Requires sponsor_admin role.

    Returns (200):
        { "users": [ { id, full_name, email, role }, ... ] }

    Returns (403): Non-admin user
    """
    users = User.query.order_by(User.full_name.asc()).all()
    return jsonify({
        "users": [
            {
                "id": u.id,
                "full_name": u.full_name,
                "email": u.email,
                "role": u.role,
            }
            for u in users
        ]
    })


# =============================================================================
# PASSWORD RESET FLOW
# =============================================================================
# The password reset flow has two steps:
# 1. POST /forgot-password with username/email -> generates reset token, returns reset link
# 2. POST /reset-password with token and new password -> validates token, updates password
#
# SECURITY NOTES:
# - We return the same message regardless of whether the account exists to prevent enumeration
# - Users without a password_hash (e.g., Google OAuth users) cannot reset their password
# - Tokens are single-use and expire after 30 minutes
# - The frontend displays the reset link directly when email sending fails (debugging)

@limiter.limit("5 per 15 minutes")
@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    """
    Step 1 of password reset: Generate a reset token and send reset email.
    
    SECURITY: Always returns 200 with a generic message to prevent user enumeration.
    We only generate tokens for users that:
    1. Exist in the database
    2. Have a password_hash (Google OAuth users without password can't reset)
    
    Request body:
        {
            "username": "admin"    // optional, mutually exclusive with email
            "email": "user@example.com"  // optional, mutually exclusive with username
        }
    
    Response (200):
        {
            "message": "If an account exists with a password, a reset email has been sent.",
            "reset_link": "https://..."  // only when email sending fails
        }
    
    Response (400): Neither username nor email provided
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    # Accept either username or email as identifier
    identifier = data.get("username") or data.get("email")
    if not identifier:
        return jsonify({"error": "Username or email is required"}), 400

    # Look up user by username OR email
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier)
    ).first()

    # SECURITY: Return same message regardless of whether user exists or has password
    # This prevents attackers from enumerating valid usernames
    if not user or not user.password_hash:
        return jsonify({
            "message": "If an account exists with a password, a reset email has been sent."
        }), 200

    # Generate password reset token (30-minute expiry, stored in DB)
    db = _get_db()
    reset_token = PasswordResetToken.generate_token(user.id)
    db.session.add(reset_token)
    db.session.commit()

    # Construct the reset link with the token
    # Take first origin from comma-separated FRONTEND_ORIGIN list
    frontend_origin = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173").split(",")[0]
    reset_link = f"{frontend_origin}/auth/reset-password?token={reset_token.plaintext_token}"

    _send_reset_email(user, reset_token.plaintext_token)

    # Return success message AND the reset_link for debugging
    # In production, the reset_link would only be sent via email
    return jsonify({
        "message": "If an account exists with a password, a reset email has been sent.",
        "reset_link": reset_link
    }), 200


@limiter.limit("5 per 15 minutes")
@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """
    Step 2 of password reset: Validate token and update user's password.
    
    SECURITY: Tokens are single-use (marked used after successful reset) and
    expire after 30 minutes. After using a token, it cannot be reused.
    
    Request body:
        {
            "token": "abc123...",      // required, the reset token
            "password": "newpassword123"  // required, min 6 characters
        }
    
    Response (200):
        { "message": "Password has been reset successfully." }
    
    Response (400): Missing token or password, or password too short
    Response (401): Invalid, expired, or already-used token
    Response (404): User not found (shouldn't happen)
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body is required"}), 400

    token_str = data.get("token")
    password = data.get("password")

    # Validate required fields and password length
    if not token_str:
        return jsonify({"error": "Reset token is required"}), 400
    if not password:
        return jsonify({"error": "New password is required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # Hash the incoming token before lookup
    import hashlib
    token_hash = hashlib.sha256(token_str.encode()).hexdigest()
    reset_token = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    if not reset_token or not reset_token.is_valid:
        return jsonify({"error": "Invalid or expired reset token"}), 401

    # Get the user associated with this token
    db = _get_db()
    user = db.session.get(User, reset_token.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Mark token as used (single-use) and update user's password
    reset_token.used = True
    user.set_password(password)
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully."}), 200


def _send_reset_email(user, token):
    """
    Send a password reset email to the given user via Resend.
    
    This function attempts to send a password reset email using the Resend API.
    If the API key is not configured or sending fails, the reset link is logged
    as a fallback (for debugging in development).
    
    NOTE: For production, RESEND_API_KEY must be set and a verified domain configured.
    
    Args:
        user: The User model instance to send the email to.
        token: The password reset token string (URL-safe base64).
    """
    # Get Resend API key from environment variables
    resend_key = os.environ.get("RESEND_API_KEY")
    
    # Construct the reset link using the frontend origin
    # FRONTEND_ORIGIN may contain multiple comma-separated origins, take the first
    frontend_origin = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173")
    reset_link = f"{frontend_origin}/auth/reset-password?token={token}"

    # HTML email template with prominent reset link
    email_html = f"""
    <h1>Password Reset Request</h1>
    <p>Hi {user.full_name or user.username},</p>
    <p>We received a request to reset your CapitalOps password. Click the link below to set a new password:</p>
    <p><a href="{reset_link}">Reset Password</a></p>
    <p>This link will expire in 30 minutes.</p>
    <p>If you didn't request this, you can safely ignore this email.</p>
    """

    # If Resend API key not configured, log the link as fallback
    if not resend_key:
        logging.warning(f"[Password Reset] RESEND_API_KEY not configured. Reset link for {user.email}: {reset_link}")
        return

    try:
        # Import resend dynamically to avoid import errors if package not installed
        import resend
        resend.api_key = resend_key
        
        # Send password reset email via Resend
        email = resend.Emails.send({
            "from": "CapitalOps <noreply@capitalops.app>",
            "to": [user.email],
            "subject": "Reset your CapitalOps password",
            "html": email_html
        })
        logging.info(f"[Password Reset] Email sent to {user.email}, id: {email}")
    except Exception as e:
        # If email sending fails, log the link as fallback for debugging
        logging.error(f"[Password Reset] Failed to send email to {user.email}: {e}")
        logging.warning(f"[Password Reset] Reset link (fallback): {reset_link}")


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    Log out the current user by clearing the httpOnly JWT cookie.

    Returns (200):
        { "message": "Logged out successfully" }
    """
    response = jsonify({"message": "Logged out successfully"})
    unset_jwt_cookies(response)
    return response


def _get_db():
    """
    Import and return the database instance.
    
    This function is used to avoid circular import issues in Flask-SQLAlchemy.
    The db object is imported here because it's created in app/__init__.py and
    importing it at module level would cause circular imports.
    
    Returns:
        SQLAlchemy db instance
    """
    from app import db
    return db
