"""
CapitalOps API - Google Authentication Route

Provides Google Sign-In token verification for the CapitalOps platform.
The frontend obtains a Google ID token via the Google Identity Services SDK,
then POSTs it to this endpoint. The backend verifies the token against Google's
public keys, finds or creates the corresponding user in the database, and
returns a CapitalOps JWT access token with the same format as the standard
/password login endpoint.

Authentication Flow:
    1. Frontend displays "Sign in with Google" button
    2. User authenticates with Google in a popup or redirect
    3. Frontend receives a Google ID token (credential)
    4. Frontend POSTs { "credential": "<google_id_token>" } to /api/v1/auth/google
    5. Backend verifies the token signature and claims via google-auth library
    6. Backend finds existing user by google_id or email, or creates a new account
    7. Backend returns CapitalOps JWT + user profile + isNewUser flag

Alternative OAuth Flow (server-side redirect):
    1. Frontend calls GET /api/v1/auth/google/gauth to get Google's consent URL
    2. Frontend opens URL in popup, user grants permission
    3. Google redirects to /api/v1/auth/google/callback with ?code=xxx
    4. Backend exchanges code for tokens, verifies id_token
    5. Backend redirects to FRONTEND_ORIGIN?google_token=<jwt>

Security Considerations:
    - GOOGLE_OAUTH_CLIENT_ID must match the Web Client ID configured in Google Cloud Console
    - The google-auth library verifies token signature, expiration, issuer, and audience
    - Email must be verified by Google before account creation/link
    - Account linking checks that no two Google accounts claim the same email address
    - New Google users receive the 'investor_tier1' role by default

New User Default Role:
    First-time Google sign-in users are assigned the 'investor_tier1' role.
    An admin can promote them to a higher role via the admin panel.

Environment Variables:
    GOOGLE_OAUTH_CLIENT_ID     — Google Cloud OAuth 2.0 Web Client ID
    GOOGLE_OAUTH_CLIENT_SECRET — Google Cloud OAuth 2.0 Client Secret (for server-side flow)
    FRONTEND_ORIGIN            — Frontend URL for redirect after OAuth callback
"""

import os
import logging

from flask import Blueprint, request, jsonify, redirect
from flask_jwt_extended import create_access_token, set_access_cookies
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from app import db, limiter
from app.models import User

logger = logging.getLogger(__name__)

google_auth_bp = Blueprint("google_auth", __name__)

# Default role assigned to new users who sign in via Google for the first time.
# Admins can upgrade their role later through the application.
# Using investor_tier1 as the default ensures new Google users have limited
# but functional access while awaiting admin review.
DEFAULT_GOOGLE_USER_ROLE = "investor_tier1"


@google_auth_bp.route("/status", methods=["GET"])
def google_status():
    """
    Check whether Google OAuth is configured and available.

    This endpoint is used by the frontend to determine whether to show
    the Google Sign-In button alongside other auth methods.

    Returns (200):
        {
            "enabled": true/false,    — Whether Google auth is active
            "configured": true/false  — Whether GOOGLE_OAUTH_CLIENT_ID is set
        }
    """
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    return jsonify({
        "enabled": bool(client_id),
        "configured": bool(client_id),
    })


@google_auth_bp.route("/gauth", methods=["GET"])
def google_redirect():
    """
    Generate Google's OAuth 2.0 consent URL and return it to the frontend.

    The frontend uses this endpoint to obtain the URL for Google's consent
    screen, which is then opened in a popup window. After the user grants
    permission, Google redirects to /api/v1/auth/google/callback.

    The returned URL includes:
    - client_id: Identifies CapitalOps to Google
    - redirect_uri: Our callback endpoint (HTTPS required by Google)
    - response_type=code: Authorization code flow (not implicit)
    - scope=openid email profile: Requests read access to user profile data
    - access_type=offline: Requests a refresh token for future use
    - prompt=select_account: Forces account selection (avoids cached grant)

    Railway-specific handling:
    - On Railway, RAILWAY_PUBLIC_DOMAIN provides the public HTTPS URL
    - The redirect_uri must use HTTPS even though Railway routes internally over HTTP

    Returns (200):
        { "authUrl": "https://accounts.google.com/o/oauth2/v2/auth?..." }
    Returns (400):
        { "error": "Google OAuth not configured" } — if env var is missing
    """
    import urllib.parse
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    if not client_id:
        return jsonify({"error": "Google OAuth not configured"}), 400

    # Railway uses https externally but http internally
    # RAILWAY_PUBLIC_DOMAIN is set automatically on Railway
    railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if railway_domain:
        backend_url = f"https://{railway_domain}"
    else:
        backend_url = request.url_root.rstrip("/")

    # Always use https for the redirect_uri (Google requires it)
    redirect_uri = backend_url.replace("http://", "https://") + "/api/v1/auth/google/callback"

    params = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
    })

    return jsonify({
        "authUrl": f"https://accounts.google.com/o/oauth2/v2/auth?{params}"
    })


@google_auth_bp.route("/callback", methods=["GET"])
def google_callback():
    """
    Handle the OAuth 2.0 callback from Google after user consent.

    Google redirects here with ?code=xxx after the user approves access.
    This endpoint exchanges the authorization code for tokens, verifies
    the id_token, finds or creates the user, and redirects to the frontend
    with the JWT access token in the URL.

    The frontend is expected to:
    1. Parse the google_token query parameter from the URL
    2. Store it as the authentication token
    3. Close the popup window

    Security considerations:
    - The authorization code is single-use
    - The id_token is verified against Google's public keys
    - Email verification is enforced (Google requires this for OAuth)
    - Account takeover prevention via google_id/email conflict checks

    Returns:
    - HTTP 302 redirect to FRONTEND_ORIGIN?google_token=<jwt> on success
    - HTML script tag that posts message to opener window on error
      (used to communicate errors back to the popup and close it)
    """
    import urllib.parse
    code = request.args.get("code")
    error = request.args.get("error")

    # Surface errors to the popup via window.postMessage
    if error:
        return f"<script>window.opener.postMessage({{error: '{error}'}}, '*'); window.close();</script>", 400

    if not code:
        return f"<script>window.opener.postMessage({{error: 'No authorization code'}}, '*'); window.close();</script>", 400

    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    if not client_secret:
        return f"<script>window.opener.postMessage({{error: 'Google OAuth not fully configured'}}, '*'); window.close();</script>", 500

    # Reconstruct the redirect_uri used in the original request
    # Must match exactly for Google to accept the code exchange
    railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if railway_domain:
        backend_url = f"https://{railway_domain}"
    else:
        backend_url = request.url_root.rstrip("/")
    redirect_uri = backend_url.replace("http://", "https://") + "/api/v1/auth/google/callback"

    # Exchange the authorization code for tokens at Google's token endpoint
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    import requests as req
    try:
        token_resp = req.post(token_url, data=token_data, timeout=30)
        token_json = token_resp.json()
    except Exception as e:
        msg = str(e)
        return f"<script>window.opener.postMessage({{error: 'Failed: {msg}'}}, '*'); window.close();</script>", 500

    if token_resp.status_code != 200:
        return f"<script>window.opener.postMessage({{error: 'Token exchange failed'}}, '*'); window.close();</script>", 400

    id_token = token_json.get("id_token")
    if not id_token:
        return f"<script>window.opener.postMessage({{error: 'No id_token'}}, '*'); window.close();</script>", 400

    # Verify and decode the id_token using Google's OAuth 2.0 public keys
    # This confirms the token was issued by Google and hasn't been tampered with
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests

    try:
        idinfo = google_id_token.verify_oauth2_token(id_token, google_requests.Request(), client_id)
    except ValueError as e:
        msg = str(e)
        return f"<script>window.opener.postMessage({{error: 'Invalid token: {msg}'}}, '*'); window.close();</script>", 401

    # Extract verified user information from the token claims
    google_sub = idinfo["sub"]           # Google's unique user ID (stable, never reused)
    email = idinfo.get("email", "")
    email_verified = idinfo.get("email_verified", False)
    given_name = idinfo.get("given_name", "")
    family_name = idinfo.get("family_name", "")
    full_name = idinfo.get("name", f"{given_name} {family_name}".strip())

    # Reject unverified emails — Google allows unverified emails on some accounts
    if not email_verified:
        return f"<script>window.opener.postMessage({{error: 'Email not verified'}}, '*'); window.close();</script>", 401

    # --- User Lookup / Creation ---
    # Three-step strategy with safety checks to prevent account takeover:
    #   1. Find by google_id (returning user who has signed in with Google before)
    #   2. Find by email (existing username/password user now linking Google)
    #   3. Create new user (brand new signup via Google)

    from app import db
    from app.models import User
    from flask_jwt_extended import create_access_token

    user = User.query.filter_by(google_id=google_sub).first()
    is_new_user = False

    if not user:
        # Step 2: Check if email already has an account (linking flow)
        user = User.query.filter_by(email=email).first()
        if user:
            # Only link if no Google account is already attached
            # If a different Google account is already linked, reject to prevent
            # account takeover by someone controlling the same email on another
            # Google workspace
            if user.google_id is not None and user.google_id != google_sub:
                return f"<script>window.opener.postMessage({{error: 'Email conflict'}}, '*'); window.close();</script>", 409
            user.google_id = google_sub
            if not user.full_name:
                user.full_name = full_name
        else:
            # Step 3: Create a brand new user account
            # Generate a unique username by appending a counter if needed
            base_username = email.split("@")[0]
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1

            user = User(
                username=username,
                email=email,
                role="investor_tier1",
                full_name=full_name,
                google_id=google_sub,
                password_hash=None,  # Google-only accounts have no password
            )
            db.session.add(user)
            is_new_user = True

        db.session.commit()

    # Issue a CapitalOps JWT with the same structure as the /login endpoint
    access_token = create_access_token(identity=str(user.id), additional_claims={"role": user.role})

    # Redirect to frontend with token in URL fragment — the cookie handles auth
    # The fragment (#) is never sent to the server, so it's more secure than query params
    frontend_url = os.environ.get("FRONTEND_ORIGIN", "https://capitalops.vercel.app")
    if frontend_url == "*":
        frontend_url = "https://capitalops.vercel.app"

    response = redirect(f"{frontend_url}/auth/callback#google_token={access_token}")
    set_access_cookies(response, access_token)
    return response


@limiter.limit("20 per minute")
@google_auth_bp.route("/", methods=["POST"])
def google_login():
    """
    Verify a Google ID token and return a CapitalOps JWT (primary Google Sign-In endpoint).

    This is the main entry point for the frontend's Google Sign-In flow.
    It receives a Google ID token (from the Google Sign-In SDK's One Tap
    or button flow), verifies it cryptographically, and returns a session JWT.

    Request Format:
        Content-Type: application/json
        Body: { "credential": "<google_id_token_string>" }

    The 'credential' field contains the Google ID token returned by:
    - Google One Tap (gsi/client library)
    - Google Sign-In button (google.accounts.id.renderButton)
    - Any OAuth 2.0 library that returns an id_token

    Verification Steps:
        1. Validate GOOGLE_OAUTH_CLIENT_ID environment variable is configured
        2. Parse request body and extract 'credential' field
        3. Verify the Google ID token signature + claims using google-auth library
           This checks: token signature, expiration, issuer (accounts.google.com),
           and audience (GOOGLE_OAUTH_CLIENT_ID)
        4. Confirm email_verified=true in token claims
        5. Find existing user by google_id (returning Google user)
           OR find by email and link Google account (linking flow)
           OR create new user with investor_tier1 role (new signup)
        6. Issue a CapitalOps JWT with same format as /login endpoint

    Returns on success (200):
        {
            "accessToken": "<jwt_access_token>",   — CapitalOps JWT session token
            "user": {                               — User profile object
                "id": 123,
                "username": "...",
                "email": "...",
                "role": "investor_tier1",
                "full_name": "...",
                ...
            },
            "isNewUser": true/false                 — Whether account was just created
        }

    Returns on failure:
        400 — Missing credential or GOOGLE_OAUTH_CLIENT_ID not configured
              {
                  "error": "Google authentication is not configured on this server"
                  "error": "Google credential token is required"
              }
        401 — Google token verification failed (invalid, expired, wrong audience)
              {
                  "error": "Invalid Google token"
                  "error": "Google email is not verified"
              }
        409 — Email already linked to a different Google account
              {
                  "error": "This email is already linked to a different Google account"
              }

    Security Considerations:
        - Token verification uses Google's public keys (fetched and cached)
        - Signature, expiration, issuer, and audience are all validated
        - email_verified claim must be true (no unverified emails)
        - Account linking checks prevent a user from stealing another user's email
        - Race condition handling for concurrent new-user requests
    """
    # Retrieve the Google Client ID from environment
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    if not client_id:
        logger.error("GOOGLE_OAUTH_CLIENT_ID environment variable is not set")
        return jsonify({
            "error": "Google authentication is not configured on this server"
        }), 400

    # Parse the request body
    data = request.get_json()
    if not data or not data.get("credential"):
        return jsonify({"error": "Google credential token is required"}), 400

    credential = data["credential"]

    # Verify the Google ID token using Google's public keys.
    # This performs cryptographic verification of:
    #   - Token signature (using Google's RSA public keys)
    #   - Token expiration (rejecting expired tokens)
    #   - Issuer (must be accounts.google.com or https://accounts.google.com)
    #   - Audience (must match our GOOGLE_OAUTH_CLIENT_ID)
    try:
        idinfo = google_id_token.verify_oauth2_token(
            credential,
            google_requests.Request(),
            client_id,
        )
    except ValueError as e:
        # Token is invalid — could be expired, wrong audience, bad signature, etc.
        # Log the failure for security monitoring but return generic error to client
        logger.warning("Google token verification failed: %s", str(e))
        return jsonify({"error": "Invalid Google token"}), 401

    # Extract user info from the verified token claims
    # These fields are verified by Google before issuing the token
    google_sub = idinfo["sub"]           # Google's unique user ID (stable across sessions)
    email = idinfo.get("email", "")
    email_verified = idinfo.get("email_verified", False)
    given_name = idinfo.get("given_name", "")
    family_name = idinfo.get("family_name", "")
    full_name = idinfo.get("name", f"{given_name} {family_name}".strip())

    # Require a verified email — Google occasionally returns unverified emails
    # for accounts that are still in the process of being created
    if not email_verified:
        return jsonify({"error": "Google email is not verified"}), 401

    # --- User Lookup / Creation ---
    # Uses a three-step strategy with safety checks to prevent account takeover.
    # This mirrors the OAuth callback flow for consistency.
    is_new_user = False

    # Strategy 1: Find by google_id (returning user who has signed in with Google before)
    user = User.query.filter_by(google_id=google_sub).first()

    if not user:
        # Strategy 2: Find by email (existing account created via username/password,
        # now linking their Google account for the first time)
        user = User.query.filter_by(email=email).first()
        if user:
            # Safety check: only link if the user has no Google account linked yet.
            # If a different Google account is already linked, reject to prevent
            # account takeover by someone who controls the same email on a different
            # Google workspace.
            if user.google_id is not None and user.google_id != google_sub:
                logger.warning(
                    "Google link conflict: email=%s already linked to google_id=%s, "
                    "attempted with google_id=%s",
                    email, user.google_id, google_sub
                )
                return jsonify({
                    "error": "This email is already linked to a different Google account"
                }), 409

            # Link the Google account to the existing user
            user.google_id = google_sub
            if not user.full_name:
                user.full_name = full_name
            db.session.commit()
            logger.info("Linked Google account to existing user: %s", email)

    if not user:
        # Strategy 3: Create a brand new user account
        # Generate a unique username from the email prefix.
        # Append a counter if the base username is already taken.
        base_username = email.split("@")[0]
        username = base_username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1

        try:
            user = User(
                username=username,
                email=email,
                role=DEFAULT_GOOGLE_USER_ROLE,
                full_name=full_name,
                google_id=google_sub,
                password_hash=None,  # No password for Google-only accounts
            )
            db.session.add(user)
            db.session.commit()
            is_new_user = True
            logger.info("Created new Google user: %s (role=%s)", email, DEFAULT_GOOGLE_USER_ROLE)
        except Exception:
            # Race condition: another request created this user between our
            # check above and the INSERT. Roll back and re-query to find them.
            db.session.rollback()
            user = User.query.filter_by(google_id=google_sub).first()
            if not user:
                user = User.query.filter_by(email=email).first()
            if not user:
                logger.error("Failed to create or find Google user: %s", email)
                return jsonify({"error": "Account creation failed, please try again"}), 500

    # Issue a CapitalOps JWT with the same structure as the /login endpoint
    # identity=str(user.id) sets the JWT subject claim
    # additional_claims={"role": user.role} embeds role for role_required() checks
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role},
    )

    from flask import make_response

    response = make_response(jsonify({
        "accessToken": access_token,
        "user": user.to_dict(),
        "isNewUser": is_new_user,
    }))
    set_access_cookies(response, access_token)
    return response
