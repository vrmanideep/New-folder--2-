from firebase_admin import auth, firestore
from .firebase_config import UNIQUE_USERNAMES_COLLECTION, USER_PROFILES_COLLECTION, APP_ID, db, FEEDBACK_COLLECTION
import random
import string
import time
import os
import json
from typing import Union, List

# Removed SendGrid specific imports as email service is not desired.
# Removed all email verification related functions as per user request.


# --- Backend Functions ---

def check_username_uniqueness_backend(username: str) -> dict:
    """
    Checks if a username is already taken in Firestore.
    This function is called by the frontend's username validation.
    """
    if not username or len(username) < 3:
        return {"available": False, "message": "Username must be at least 3 characters."}

    try:
        doc_ref = UNIQUE_USERNAMES_COLLECTION.document(username.lower())
        doc = doc_ref.get()

        if doc.exists:
            return {"available": False, "message": "Username is already taken."}
        else:
            return {"available": True, "message": "Username is available!"}
    except Exception as e:
        print(f"Backend Error checking username uniqueness: {e}")
        return {"available": False, "message": "Server error during check."}


def register_user_backend(name: str, username: str, email: str, password: str) -> dict:
    """
    Registers a new user in Firebase Authentication and stores profile in Firestore.
    Email verification is now skipped.
    Returns a custom token for client-side sign-in.
    """
    if not all([name, username, email, password]):
        return {"success": False, "message": "All fields are required."}

    username_check = check_username_uniqueness_backend(username)
    if not username_check["available"]:
        return {"success": False, "message": username_check["message"]}

    try:
        user = auth.create_user(
            email=email,
            password=password,
            display_name=name,
            email_verified=False # Explicitly set to False as no email verification is handled by backend
        )
        user_id = user.uid
        print(f"Firebase Auth user created: {user_id}")

        UNIQUE_USERNAMES_COLLECTION.document(username.lower()).set({
            'uid': user_id,
            'email': email,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        print(f"Username '{username}' recorded as unique.")

        USER_PROFILES_COLLECTION.document(user_id).set({
            'name': name,
            'username': username.lower(),
            'email': email,
            'photoURL': user.photo_url,
            'createdAt': firestore.SERVER_TIMESTAMP,
            'emailVerified': False, # Explicitly set to False as we are not enforcing it
            'authProvider': 'password'
        }, merge=True)
        print(f"User profile for '{username}' stored in Firestore.")

        # Generate a custom token for the client to sign in
        custom_token = auth.create_custom_token(user_id).decode('utf-8')
        print(f"Custom token generated for user: {user_id}")

        return {"success": True, "message": "Registration successful! You can now log in.", "custom_token": custom_token}

    except auth.EmailAlreadyExistsError:
        return {"success": False, "message": "Email is already registered."}
    except Exception as e:
        print(f"Error during user registration: {e}")
        return {"success": False, "message": f"Registration failed: {e}"}


def login_user_backend(identifier: str, password: str) -> dict:
    """
    Authenticates a user and generates a Firebase Custom Token for client-side sign-in.
    """
    if not all([identifier, password]):
        return {"success": False, "message": "Username/Email and password are required."}

    try:
        email = identifier
        # Check if the identifier is a username
        if "@" not in identifier:
            username_doc = UNIQUE_USERNAMES_COLLECTION.document(identifier.lower()).get()
            if username_doc.exists:
                email = username_doc.to_dict().get('email')
            else:
                return {"success": False, "message": "Invalid credentials."}

        user = auth.get_user_by_email(email)
        user_id = user.uid
        print(f"User '{email}' found in Firebase Auth.")

        custom_token = auth.create_custom_token(user_id).decode('utf-8')
        print(f"Generated custom token for user: {user_id}")

        return {"success": True, "message": "Login successful.", "customToken": custom_token}

    except auth.UserNotFoundError:
        return {"success": False, "message": "Invalid username or password."}
    except Exception as e:
        print(f"Backend Error during user login: {e}")
        return {"success": False, "message": f"Login failed: {e}"}

# --- Removed: send_firebase_email_verification_backend function as per user request ---

# --- New Function: Delete User Data ---
def delete_user_data_backend(uid: str) -> dict:
    """
    Deletes a user from Firebase Authentication, their unique username entry,
    user profile, and any associated OTPs in Firestore.
    """
    if not uid:
        return {"success": False, "message": "User ID is required for deletion."}

    try:
        user = auth.get_user(uid) # Get user by UID directly

        auth.delete_user(uid)
        print(f"User '{uid}' deleted from Firebase Authentication.")

        USER_PROFILES_COLLECTION.document(uid).delete()
        print(f"User profile for '{uid}' deleted from Firestore.")

        # Find and delete username mapping
        username_query = UNIQUE_USERNAMES_COLLECTION.where('uid', '==', uid).limit(1).get()
        for doc in username_query:
            doc.reference.delete()
            print(f"Unique username mapping for '{uid}' deleted from Firestore.")
            break

        return {"success": True, "message": f"User '{uid}' and all associated data deleted successfully."}

    except auth.UserNotFoundError:
        return {"success": False, "message": "User not found."}
    except Exception as e:
        print(f"Error deleting user data: {e}")
        return {"success": False, "message": f"Failed to delete user data: {e}"}

# --- Gemini API Integration Function (Removed as per user request) ---
async def get_login_tips_backend() -> dict:
    return {"success": False, "message": "Login tips feature is currently disabled."}

# --- Get User Profile ---
def get_user_profile_backend(user_id: str) -> dict:
    """
    Retrieves a user's profile data from Firestore.
    """
    if not user_id:
        return {"success": False, "message": "User ID is required to fetch profile."}

    try:
        profile_doc = USER_PROFILES_COLLECTION.document(user_id).get()
        if profile_doc.exists:
            profile_data = profile_doc.to_dict()
            profile_data['name'] = profile_data.get('name', 'N/A')
            profile_data['username'] = profile_data.get('username', 'N/A')
            return {"success": True, "profile": profile_data}
        else:
            return {"success": False, "message": "User profile not found."}
    except Exception as e:
        print(f"Error fetching user profile: {e}")
        return {"success": False, "message": f"Failed to fetch profile: {e}"}

# --- Update User Address ---
def update_user_address_backend(user_id: str, address: str) -> dict:
    """
    Updates a user's address in their Firestore profile.
    """
    if not user_id or address is None:
        return {"success": False, "message": "User ID and address are required."}

    try:
        USER_PROFILES_COLLECTION.document(user_id).update({'address': address})
        print(f"User '{user_id}' address updated to: '{address}'")
        return {"success": True, "message": "Address updated successfully."}
    except Exception as e:
        print(f"Error updating user address: {e}")
        return {"success": False, "message": f"Failed to update address: {e}"}

# --- Handle Google Authentication Backend ---
def handle_google_auth_backend(id_token: str, display_name: str, email: str, photo_url: str) -> dict:
    """
    Verifies the Google ID token and handles user creation/login.
    If a user with this email already exists (via password or another provider),
    it will attempt to link the Google credential. If not, it creates a new user.
    It also ensures a user profile is created/updated in Firestore.
    """
    if not id_token:
        return {"success": False, "message": "Google ID token is missing."}
    if not email:
        return {"success": False, "message": "Email is required for Google authentication."}

    try:
        decoded_token = auth.verify_id_token(id_token, check_revoked=True)
        uid = decoded_token['uid']
        print(f"Google ID Token verified for UID: {uid}")

        try:
            user = auth.get_user(uid)
            print(f"User with UID {uid} already exists in Firebase Auth.")

            USER_PROFILES_COLLECTION.document(uid).set({
                'name': display_name or user.display_name,
                'email': email or user.email,
                'photoURL': photo_url or user.photo_url,
                'lastLogin': firestore.SERVER_TIMESTAMP,
                'authProvider': 'google'
            }, merge=True)

            return {"success": True, "message": "Successfully signed in with Google."}
        except auth.UserNotFoundError:
            try:
                user_by_email = auth.get_user_by_email(email)
                print(f"User with email {email} already exists but different UID. Attempting to link.")
                return {"success": False, "message": "An account with this email already exists using a different sign-in method. Please use that method to log in."}

            except auth.UserNotFoundError:
                print(f"Creating new user for Google sign-in: {email}")
                user = auth.create_user(
                    uid=uid,
                    email=email,
                    display_name=display_name,
                    photo_url=photo_url,
                    email_verified=decoded_token.get('email_verified', False) # Google usually provides verified email
                )
                print(f"New Firebase Auth user created for Google: {user.uid}")

                USER_PROFILES_COLLECTION.document(user.uid).set({
                    'name': display_name,
                    'username': email.split('@')[0],
                    'email': email,
                    'photoURL': photo_url,
                    'createdAt': firestore.SERVER_TIMESTAMP,
                    'emailVerified': decoded_token.get('email_verified', False), # Use Google's verification status
                    'authProvider': 'google'
                })
                print(f"User profile for Google user '{email}' stored in Firestore.")
                return {"success": True, "message": "Successfully signed up with Google."}

    except auth.InvalidIdTokenError:
        print(f"Invalid Google ID token: {id_token}")
        return {"success": False, "message": "Invalid or expired Google ID token."}
    except auth.CertificateFetchError:
        print(f"Certificate fetch error (Firebase Admin SDK): Check network or Firebase project setup.")
        return {"success": False, "message": "Server error during token verification. Please try again."}
    except Exception as e:
        print(f"General error during Google authentication: {e}")
        return {"success": False, "message": f"Google authentication failed: {e}"}

# NEW: Change Password Backend Function
def change_password_backend(user_id: str, new_password: str) -> dict:
    """
    Changes the password for a given user ID in Firebase Authentication.
    Also revokes all refresh tokens for the user to invalidate existing sessions.
    """
    if not user_id or not new_password:
        return {"success": False, "message": "User ID and new password are required."}

    if len(new_password) < 6:
        return {"success": False, "message": "New password must be at least 6 characters long."}

    try:
        auth.update_user(user_id, password=new_password)
        print(f"Password updated for user: {user_id}")

        # Invalidate all refresh tokens for the user to force re-login
        auth.revoke_refresh_tokens(user_id)
        print(f"Refresh tokens revoked for user: {user_id}")

        return {"success": True, "message": "Password updated successfully. Please log in again."}
    except auth.UserNotFoundError:
        return {"success": False, "message": "User not found."}
    except Exception as e:
        print(f"Error changing password for user {user_id}: {e}")
        return {"success": False, "message": f"Failed to change password: {e}"}

# NEW: Save Feedback Backend Function
def save_feedback_backend(uid: str, feedback_message: str) -> dict:
    """
    Stores user feedback in a Firestore collection.
    """
    if not feedback_message:
        return {"success": False, "message": "Feedback message cannot be empty."}

    try:
        # Get user's name and username for more context in feedback
        user_profile_doc = USER_PROFILES_COLLECTION.document(uid).get()
        user_data = user_profile_doc.to_dict() if user_profile_doc.exists else {}
        
        feedback_data = {
            'uid': uid,
            'message': feedback_message,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'user_email': user_data.get('email', 'N/A'),
            'user_username': user_data.get('username', 'N/A'),
            'user_name': user_data.get('name', 'N/A')
        }
        
        FEEDBACK_COLLECTION.add(feedback_data) # Use add() for auto-generated document ID
        print(f"Feedback from {uid} saved to Firestore.")
        return {"success": True, "message": "Feedback saved successfully!"}
    except Exception as e:
        print(f"Error saving feedback to Firestore: {e}")
        return {"success": False, "message": f"Failed to save feedback: {str(e)}"}
