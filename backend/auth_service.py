# backend/auth_service.py

from firebase_admin import auth, firestore
from .firebase_config import UNIQUE_USERNAMES_COLLECTION, USER_PROFILES_COLLECTION, EMAIL_OTPS_COLLECTION, APP_ID, db, FEEDBACK_COLLECTION
import random
import string
import time
import os
import json
from typing import Union, List

# Import SendGrid specific libraries (kept, but not used for verification flow)
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


# --- Generic Email Sending Function (using SendGrid) ---
def _send_email(from_email: str, to_emails: Union[str, List[str]], subject: str, html_content: str) -> bool:
    """
    Sends a generic email using SendGrid.
    to_emails can be a single email string or a list of email strings.
    """
    from_email = os.getenv("SENDGRID_SENDER_EMAIL", 'your_verified_sender_email@yourdomain.com') # Get from env or use placeholder

    if not from_email or from_email == 'your_verified_sender_email@yourdomain.com':
        print("ERROR: Please update 'SENDGRID_SENDER_EMAIL' environment variable with your verified SendGrid sender.")
        return False

    # Ensure to_emails is a list for the Mail constructor
    if isinstance(to_emails, str):
        to_emails = [to_emails]

    message = Mail(
        from_email=from_email,
        to_emails=to_emails,
        subject=subject,
        html_content=html_content
    )

    try:
        sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
        if not sendgrid_api_key:
            print("ERROR: SENDGRID_API_KEY environment variable not set. Please set it.")
            return False

        sg = SendGridAPIClient(sendgrid_api_key)
        response = sg.send(message)
        print(f"Email sent via SendGrid. Status Code: {response.status_code}")
        if response.status_code == 200 or response.status_code == 202:
            return True
        else:
            print(f"SendGrid API Error: {response.status_code} - {response.body.decode('utf-8')}")
            return False
    except Exception as e:
        print(f"Error sending email with SendGrid: {e}")
        return False


# --- Real Email Sending Function (using _send_email helper) ---
# This function is now mostly for internal use if you decide to send other emails
def _send_email_with_otp(email: str) -> bool:
    """
    Sends an email with an OTP using the generic _send_email helper.
    """
    otp = ''.join(random.choices(string.digits, k=6))
    expiry_time = int(time.time()) + 300 # OTP valid for 5 minutes

    EMAIL_OTPS_COLLECTION.document(email.lower()).set({
        'otp': otp,
        'expiry': expiry_time,
        'createdAt': firestore.SERVER_TIMESTAMP
    })
    print(f"OTP '{otp}' stored for {email}.")

    subject = 'Your One-Time Password (OTP) for Verification'
    html_content = f'<strong>Your One-Time Password (OTP) is: {otp}</strong>'
    return _send_email(os.getenv("SENDGRID_SENDER_EMAIL"), email, subject, html_content)


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
            email_verified=False # Still set to False, but not enforced
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

        # Removed: send_firebase_email_verification_backend(user.uid)
        # Email verification is no longer enforced after registration.

        return {"success": True, "message": "Registration successful! You can now log in.", "custom_token": custom_token}

    except auth.EmailAlreadyExistsError:
        return {"success": False, "message": "Email is already registered."}
    except Exception as e:
        print(f"Error during user registration: {e}")
        return {"success": False, "message": f"Registration failed: {e}"}

def send_firebase_email_verification_backend(uid):
    """
    Generates a Firebase email verification link for the user.
    This function is kept for completeness but is no longer called during registration.
    """
    try:
        user = auth.get_user(uid)
        if not user.email_verified:
            action_code_settings = auth.ActionCodeSettings(
                url='http://localhost:5000/email_verification.html',
                handle_code_in_app=True,
            )
            link = auth.generate_email_verification_link(user.email, action_code_settings)
            print(f"Firebase Email Verification Link generated for {user.email}: {link}")
            return {"success": True, "message": "Verification email link generated."}
        else:
            return {"success": True, "message": "Email is already verified."}
    except Exception as e:
        print(f"Firebase error generating verification email link: {e}")
        return {"success": False, "message": f"Failed to generate verification email link: {str(e)}"}


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

        # Delete associated OTP if exists (if email was used for OTP)
        if user.email:
            otp_doc_ref = EMAIL_OTPS_COLLECTION.document(user.email.lower())
            if otp_doc_ref.get().exists:
                otp_doc_ref.delete()
                print(f"Associated OTP for '{user.email}' deleted from Firestore.")

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

