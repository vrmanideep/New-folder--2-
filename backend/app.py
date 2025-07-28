import os
from flask import Flask, request, jsonify, send_from_directory, render_template
from functools import wraps
from firebase_admin import auth, storage, exceptions

# Relative import for auth_service.py
from .auth_service import (
    check_username_uniqueness_backend,
    register_user_backend,
    login_user_backend,
    delete_user_data_backend,
    get_login_tips_backend,
    get_user_profile_backend,
    update_user_address_backend,
    handle_google_auth_backend,
    # Removed send_firebase_email_verification_backend as per user request
    save_feedback_backend
)

# Relative import for firebase_config.py
from . import firebase_config

import asyncio

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_FOLDER = os.path.join(BASE_DIR, 'frontend')
STATIC_FOLDER = os.path.join(BASE_DIR, 'frontend')

# Define the Flask app instance at the top level
app = Flask(__name__,
            template_folder=TEMPLATE_FOLDER,
            static_folder=STATIC_FOLDER)

# Add a print statement to confirm 'app' is being defined
print("DEBUG: Flask 'app' instance defined at top level.")


def run_async(func):
    """Decorator to run async functions in Flask routes."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

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
    if firebase_config.FIREBASE_CLIENT_CONFIG.get("apiKey") == "YOUR_WEB_API_KEY":
        return jsonify({"success": False, "message": "Firebase client config not set in firebase_config.py"}), 500
    return jsonify({"success": True, "config": firebase_config.FIREBASE_CLIENT_CONFIG})


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
    email = data.get('email')
    password = data.get('password')
    result = register_user_backend(name, username, email, password)
    return jsonify(result)

# Removed /api/resend-verification-email endpoint as per user request
# @app.route('/api/resend-verification-email', methods=['POST'])
# @token_required
# def api_resend_verification_email(decoded_token):
#     user_id = decoded_token['uid']
#     result = send_firebase_email_verification_backend(user_id)
#     return jsonify(result)

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
@token_required
def api_google_auth(decoded_token):
    data = request.get_json()
    display_name = data.get('displayName')
    email = data.get('email')
    photo_url = data.get('photoURL')

    result = handle_google_auth_backend(
        id_token=request.headers.get('Authorization').split(' ')[1],
        display_name=display_name,
        email=email,
        photo_url=photo_url
    )
    return jsonify(result)

@app.route('/api/upload-profile-picture', methods=['POST'])
@token_required
def upload_profile_picture(decoded_token):
    uid = decoded_token['uid']

    if 'profilePicture' not in request.files:
        return jsonify({"success": False, "message": "No file part in the request"}), 400

    file = request.files['profilePicture']

    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400

    if file:
        try:
            bucket = storage.bucket()
            file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
            blob_name = f"profile_pictures/{uid}/profile.{file_extension}"
            blob = bucket.blob(blob_name)

            blob.upload_from_file(file, content_type=file.content_type)
            blob.make_public()
            public_url = blob.public_url

            auth.update_user(uid, photo_url=public_url)

            try:
                user_profile_ref = firebase_config.db.collection(f'artifacts/{firebase_config.APP_ID}/public/data/user_profiles').document(uid)
                user_profile_ref.update({'photoURL': public_url})
            except Exception as e:
                print(f"Warning: Could not update Firestore profile for {uid}: {e}")

            return jsonify({
                "success": True,
                "message": "Profile picture uploaded and updated successfully!",
                "photoURL": public_url
            }), 200

        except exceptions.FirebaseError as e:
            print(f"Firebase Storage or Auth error: {e}")
            return jsonify({"success": False, "message": f"Firebase error: {e}"}), 500
        except Exception as e:
            print(f"Unexpected error during profile picture upload: {e}")
            return jsonify({"success": False, "message": "An unexpected error occurred during upload."}), 500
    
    return jsonify({"success": False, "message": "File upload failed."}), 500

@app.route('/api/send-feedback', methods=['POST'])
@token_required
def api_send_feedback(decoded_token):
    uid = decoded_token['uid']
    data = request.get_json()
    feedback_message = data.get('message')

    if not feedback_message:
        return jsonify({"success": False, "message": "Feedback message cannot be empty."}), 400

    result = save_feedback_backend(uid, feedback_message)
    return jsonify(result)


# --- Serve Static Frontend Files ---
@app.route('/')
def serve_login():
    return render_template('login.html')

@app.route('/<string:page_name>.html')
def serve_html_pages(page_name):
    return render_template(f'{page_name}.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
