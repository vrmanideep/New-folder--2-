import firebase_admin
from firebase_admin import auth, firestore
from firebase_admin import credentials
from firebase_admin import exceptions

# Check if already initialized to avoid duplicate app error
if not firebase_admin._apps:
    cred = credentials.Certificate("path_to_your_service_account_key.json")
    firebase_admin.initialize_app(cred)

db = firestore.client()

def check_username_uniqueness_backend(username):
    # Check if a username exists in Firestore
    users_ref = db.collection("users")
    query = users_ref.where("username", "==", username).get()
    return len(query) == 0

def register_user_backend(email, password, username):
    try:
        user = auth.create_user(email=email, password=password)
        user_id = user.uid
        user_data = {
            "email": email,
            "username": username
        }
        db.collection("users").document(user_id).set(user_data)
        return {"success": True, "message": "User registered successfully"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def login_user_backend(email, password):
    # 🔧 You CANNOT verify password via firebase_admin SDK directly
    # This is a dummy/stub for frontend testing or to be replaced with REST API logic
    if email and password:
        return {"success": True, "message": "Login successful", "email": email}
    return {"success": False, "message": "Invalid credentials"}

def delete_user_data_backend(user_id):
    try:
        auth.delete_user(user_id)
        db.collection("users").document(user_id).delete()
        return {"success": True, "message": "User deleted successfully"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def get_login_tips_backend():
    return ["Use a strong password", "Don’t reuse passwords", "Enable 2FA when available"]

def get_user_profile_backend(user_id):
    try:
        doc = db.collection("users").document(user_id).get()
        if doc.exists:
            return doc.to_dict()
        else:
            return {"error": "User not found"}
    except Exception as e:
        return {"error": str(e)}

def update_user_address_backend(user_id, address_data):
    try:
        db.collection("users").document(user_id).update({"address": address_data})
        return {"success": True, "message": "Address updated"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def handle_google_auth_backend(token):
    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token["uid"]
        user_record = auth.get_user(uid)
        return {"success": True, "email": user_record.email}
    except Exception as e:
        return {"success": False, "message": str(e)}

def save_feedback_backend(user_id, feedback):
    try:
        db.collection("feedback").add({
            "user_id": user_id,
            "feedback": feedback
        })
        return {"success": True, "message": "Feedback saved"}
    except Exception as e:
        return {"success": False, "message": str(e)}
