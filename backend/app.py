# app.py

from flask import Flask, request, jsonify, send_from_directory
from functools import wraps
from firebase_admin import auth
from .auth_service import (
    check_username_uniqueness_backend,
    register_user_backend,
    send_otp_to_email_backend,
    verify_email_otp_backend,
    login_user_backend,
    delete_user_data_backend,
    get_login_tips_backend,
    get_user_profile_backend,
    update_user_address_backend,
    handle_google_auth_backend # Import the new Google auth function
)
from firebase_config import FIREBASE_CLIENT_CONFIG
import firebase_config
import os
import asyncio

# Initialize Flask app, explicitly setting the static folder to the current directory
app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))

# --- Helper for async functions in Flask routes ---
def run_async(func):
    """Decorator to run async functions in Flask routes."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

# --- Token Verification Decorator ---
def token_required(f):
    """
    Decorator to verify Firebase ID Tokens for protected API routes.
    Extracts the token from the Authorization header, verifies it,
    and passes the decoded token (containing user_id) to the route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        id_token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                id_token = auth_header.split(' ')[1]

        if not id_token:
            return jsonify({"message": "Authorization token is missing!"}), 401

        try:
            decoded_token = auth.verify_id_token(id_token)
            kwargs['decoded_token'] = decoded_token
        except Exception as e:
            print(f"Token verification failed: {e}")
            return jsonify({"message": "Token is invalid or expired!"}), 401

        return f(*args, **kwargs)
    return decorated_function

# --- API Endpoints ---

@app.route('/api/firebase-config', methods=['GET'])
def api_firebase_config():
    """
    Endpoint to provide Firebase client-side configuration to the frontend.
    """
    if FIREBASE_CLIENT_CONFIG.get("apiKey") == "YOUR_WEB_API_KEY":
        return jsonify({"success": False, "message": "Firebase client config not set in firebase_config.py"}), 500
    return jsonify({"success": True, "config": FIREBASE_CLIENT_CONFIG})


@app.route('/api/check-username', methods=['GET'])
def api_check_username():
    username = request.args.get('username')
    result = check_username_uniqueness_backend(username)
    return jsonify(result)

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')
    # Email is no longer directly collected from frontend, backend generates dummy
    result = register_user_backend(name, username, password)
    return jsonify(result)

@app.route('/api/send-otp', methods=['POST'])
def api_send_otp():
    data = request.get_json()
    email = data.get('email')
    result = send_otp_to_email_backend(email)
    return jsonify(result)

@app.route('/api/verify-otp', methods=['POST'])
def api_verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    result = verify_email_otp_backend(email, otp)
    return jsonify(result)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    identifier = data.get('identifier')
    password = data.get('password')
    result = login_user_backend(identifier, password)
    return jsonify(result)

@app.route('/api/delete-user', methods=['POST'])
@token_required
def api_delete_user(decoded_token):
    identifier = request.get_json().get('identifier')
    result = delete_user_data_backend(identifier)
    return jsonify(result)

@app.route('/api/login-tips', methods=['GET'])
@run_async
def api_get_login_tips():
    result = get_login_tips_backend()
    return jsonify(result)

@app.route('/api/user-profile', methods=['GET'])
@token_required
def api_get_user_profile(decoded_token):
    user_id = decoded_token['uid']
    result = get_user_profile_backend(user_id)
    return jsonify(result)

@app.route('/api/update-address', methods=['POST'])
@token_required
def api_update_address(decoded_token):
    user_id = decoded_token['uid']
    data = request.get_json()
    address = data.get('address')

    if address is None:
        return jsonify({"success": False, "message": "Address field is missing."}), 400

    result = update_user_address_backend(user_id, address)
    return jsonify(result)

@app.route('/api/google-auth', methods=['POST'])
@token_required # The token here is the Google ID token from the client
def api_google_auth(decoded_token):
    """
    Endpoint to handle Google Sign-In/Sign-Up.
    The 'decoded_token' here is the Google ID token verified by Firebase Auth Admin SDK.
    """
    # Extract data sent from the frontend (Firebase Auth user object details)
    data = request.get_json()
    display_name = data.get('displayName')
    email = data.get('email')
    photo_url = data.get('photoURL')

    # The 'decoded_token' already contains the 'uid' and other Google claims
    # (like 'email', 'email_verified', 'name', 'picture').
    # We pass these to the backend logic.
    result = handle_google_auth_backend(
        id_token=request.headers.get('Authorization').split(' ')[1], # Pass the raw ID token for verification
        display_name=display_name,
        email=email,
        photo_url=photo_url
    )
    return jsonify(result)


# --- Serve Static Frontend Files ---
@app.route('/')
def serve_login():
    return send_from_directory(app.static_folder, 'login.html')

@app.route('/<path:filename>')
def serve_static_files(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

