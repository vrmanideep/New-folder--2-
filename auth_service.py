# auth_service.py

from firebase_admin import auth, firestore
from firebase_config import UNIQUE_USERNAMES_COLLECTION, USER_PROFILES_COLLECTION, EMAIL_OTPS_COLLECTION, APP_ID
import random
import string
import time
import os
import json

# Import SendGrid specific libraries
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# --- Real Email Sending Function (using SendGrid) ---
def _send_email_with_otp(email: str, otp: str):
    """
    Sends an email with an OTP using SendGrid.
    """
    from_email = 'manideepphaniharam2007@gmail.com' # Update this with your verified sender email
    if not from_email or from_email == 'your_verified_sender_email@yourdomain.com':
        print("ERROR: Please update 'from_email' in auth_service.py with your verified SendGrid sender.")
        return False

    message = Mail(
        from_email=from_email,
        to_emails=email,
        subject='Your One-Time Password (OTP) for Verification',
        html_content=f'<strong>Your One-Time Password (OTP) is: {otp}</strong>'
    )

    try:
        sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
        if not sendgrid_api_key:
            print("ERROR: SENDGRID_API_KEY environment variable not set. Please set it in your terminal.")
            return False

        sg = SendGridAPIClient(sendgrid_api_key)
        response = sg.send(message)
        print(f"Email sent via SendGrid. Status Code: {response.status_code}")
        if response.status_code == 200 or response.status_code == 202:
            return True
        else:
            print(f"SendGrid API Error: {response.status_code} - {response.body}")
            return False
    except Exception as e:
        print(f"Error sending email with SendGrid: {e}")
        return False


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


def register_user_backend(name: str, username: str, password: str) -> dict:
    """
    Registers a new user in Firebase Authentication and stores profile in Firestore.
    Generates a dummy email for Firebase Auth.
    """
    if not all([name, username, password]):
        return {"success": False, "message": "All fields are required."}

    username_check = check_username_uniqueness_backend(username)
    if not username_check["available"]:
        return {"success": False, "message": username_check["message"]}

    try:
        dummy_email = f"{username.lower()}@{APP_ID}.temp.com"
        print(f"Generated dummy email for {username}: {dummy_email}")

        user = auth.create_user(
            email=dummy_email,
            password=password,
            display_name=name,
            email_verified=False
        )
        user_id = user.uid
        print(f"Firebase Auth user created: {user_id}")

        UNIQUE_USERNAMES_COLLECTION.document(username.lower()).set({
            'userId': user_id,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        print(f"Username '{username}' recorded as unique.")

        USER_PROFILES_COL.document(user_id).set({
            'name': name,
            'username': username.lower(),
            'email': dummy_email,
            'createdAt': firestore.SERVER_TIMESTAMP,
            'emailVerified': False,
            'authProvider': 'password' # Indicate password provider
        })
        print(f"User profile for '{username}' stored in Firestore.")

        return {"success": True, "message": "Registration successful! You can now log in."}

    except auth.EmailAlreadyExistsError:
        return {"success": False, "message": "An account with this username might already exist or a system email conflict occurred."}
    except Exception as e:
        print(f"Error during user registration: {e}")
        return {"success": False, "message": f"Registration failed: {e}"}


def send_otp_to_email_backend(email: str) -> dict:
    """
    Checks if an email exists in Firebase Auth and sends an OTP for verification.
    Stores the OTP in Firestore with an expiry.
    """
    if not email:
        return {"success": False, "message": "Email is required."}

    try:
        user = auth.get_user_by_email(email)
        user_id = user.uid

        otp = ''.join(random.choices(string.digits, k=6))
        expiry_time = int(time.time()) + 300

        EMAIL_OTPS_COLLECTION.document(email.lower()).set({
            'otp': otp,
            'userId': user_id,
            'expiry': expiry_time,
            'createdAt': firestore.SERVER_TIMESTAMP
        })
        print(f"OTP '{otp}' stored for {email}.")

        if _send_email_with_otp(email, otp):
            return {"success": True, "message": "OTP sent successfully."}
        else:
            return {"success": False, "message": "Failed to send email."}

    except auth.UserNotFoundError:
        return {"success": False, "message": "Email not registered. Please register first."}
    except Exception as e:
        print(f"Backend Error sending OTP: {e}")
        return {"success": False, "message": f"Failed to send OTP: {e}"}


def verify_email_otp_backend(email: str, otp: str) -> dict:
    """
    Verifies the provided OTP against the stored one.
    If valid, marks the user's email as verified in Firebase Auth and Firestore.
    """
    if not all([email, otp]):
        return {"success": False, "message": "Email and OTP are required."}

    try:
        otp_doc_ref = EMAIL_OTPS_COLLECTION.document(email.lower())
        otp_doc = otp_doc_ref.get()

        if not otp_doc.exists:
            return {"success": False, "message": "No OTP found for this email or it has expired."}

        stored_otp_data = otp_doc.to_dict()
        stored_otp = stored_otp_data.get('otp')
        expiry_time = stored_otp_data.get('expiry')
        user_id = stored_otp_data.get('userId')

        if expiry_time and int(time.time()) > expiry_time:
            otp_doc_ref.delete()
            return {"success": False, "message": "OTP has expired. Please request a new one."}

        if stored_otp == otp:
            auth.update_user(user_id, email_verified=True)
            USER_PROFILES_COL.document(user_id).update({'emailVerified': True})
            otp_doc_ref.delete()

            return {"success": True, "message": "Email verified successfully."}
        else:
            return {"success": False, "message": "Invalid OTP."}

    except auth.UserNotFoundError:
        return {"success": False, "message": "User not found for this email."}
    except Exception as e:
        print(f"Backend Error verifying OTP: {e}")
        return {"success": False, "message": f"Verification failed: {e}"}


def login_user_backend(identifier: str, password: str) -> dict:
    """
    Authenticates a user and generates a Firebase Custom Token for client-side sign-in.
    """
    if not all([identifier, password]):
        return {"success": False, "message": "Username/Email and password are required."}

    try:
        is_email = "@" in identifier and "." in identifier
        user_id = None

        if is_email:
            email = identifier
            user = auth.get_user_by_email(email)
            user_id = user.uid
            print(f"User '{email}' found in Firebase Auth.")
        else:
            username = identifier.lower()
            query_ref = USER_PROFILES_COL.where('username', '==', username).limit(1)
            docs = query_ref.stream()
            user_data = None
            for doc in docs:
                user_data = doc.to_dict()
                user_id = doc.id
                break

            if not user_data:
                return {"success": False, "message": "Invalid username or password."}

            user = auth.get_user(user_id)
            print(f"User '{username}' found in Firebase Auth via username lookup.")

        custom_token = auth.create_custom_token(user_id).decode('utf-8')
        print(f"Generated custom token for user: {user_id}")

        return {"success": True, "message": "Login successful.", "customToken": custom_token}

    except auth.UserNotFoundError:
        return {"success": False, "message": "Invalid username or password."}
    except Exception as e:
        print(f"Backend Error during user login: {e}")
        return {"success": False, "message": f"Login failed: {e}"}

# --- New Function: Delete User Data ---
def delete_user_data_backend(identifier: str) -> dict:
    """
    Deletes a user from Firebase Authentication, their unique username entry,
    user profile, and any associated OTPs in Firestore.
    Identifier can be email or username.
    """
    if not identifier:
        return {"success": False, "message": "Identifier (email or username) is required for deletion."}

    user_id = None
    email = None
    username_to_delete = None

    try:
        # 1. Try to get user by email first
        try:
            user = auth.get_user_by_email(identifier)
            user_id = user.uid
            email = user.email
            profile_doc = USER_PROFILES_COL.document(user_id).get()
            if profile_doc.exists:
                username_to_delete = profile_doc.to_dict().get('username')
        except auth.UserNotFoundError:
            query_ref = USER_PROFILES_COL.where('username', '==', identifier.lower()).limit(1)
            docs = query_ref.stream()
            user_data = None
            for doc in docs:
                user_data = doc.to_dict()
                user_id = doc.id
                email = user_data.get('email')
                username_to_delete = user_data.get('username')
                break

            if not user_id:
                return {"success": False, "message": "User not found with the provided identifier."}

        if not user_id:
            return {"success": False, "message": "Could not find a user with the provided identifier."}

        auth.delete_user(user_id)
        print(f"User '{user_id}' deleted from Firebase Authentication.")

        USER_PROFILES_COL.document(user_id).delete()
        print(f"User profile for '{user_id}' deleted from Firestore.")

        if username_to_delete:
            UNIQUE_USERNAMES_COLLECTION.document(username_to_delete).delete()
            print(f"Unique username '{username_to_delete}' deleted from Firestore.")

        if email:
            otp_doc_ref = EMAIL_OTPS_COLLECTION.document(email.lower())
            if otp_doc_ref.get().exists:
                otp_doc_ref.delete()
                print(f"Associated OTP for '{email}' deleted from Firestore.")

        return {"success": True, "message": f"User '{identifier}' and all associated data deleted successfully."}

    except auth.UserNotFoundError:
        return {"success": False, "message": "User not found with the provided identifier."}
    except Exception as e:
        print(f"Error deleting user data: {e}")
        return {"success": False, "message": f"Failed to delete user data: {e}"}

# --- Gemini API Integration Function ---
async def get_login_tips_backend() -> dict:
    """
    Calls the Gemini API to generate general login troubleshooting tips.
    """
    try:
        prompt = "Provide 3-5 concise, general troubleshooting tips for a user who is having trouble logging into a web application. Format them as a numbered list. Do not include any specific application names or technical jargon like 'Firebase' or 'Firestore'. Focus on common user-side issues like password, caps lock, internet, etc."
        api_key = os.environ.get('GEMINI_API_KEY', '')

        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.7,
                "topP": 0.95,
                "topK": 40,
                "maxOutputTokens": 200,
            }
        }

        import requests
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
        headers = {'Content-Type': 'application/json'}

        response = requests.post(api_url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()

        result = response.json()

        if result.get("candidates") and len(result["candidates"]) > 0 and \
           result["candidates"][0].get("content") and \
           result["candidates"][0]["content"].get("parts") and \
           len(result["candidates"][0]["content"]["parts"]) > 0:
            tips = result["candidates"][0]["content"]["parts"][0]["text"]
            return {"success": True, "tips": tips}
        else:
            print(f"Gemini API response structure unexpected: {result}")
            return {"success": False, "message": "Could not generate tips. Unexpected API response."}

    except requests.exceptions.RequestException as req_err:
        print(f"Network or API request error with Gemini: {req_err}")
        return {"success": False, "message": f"Error connecting to AI service: {req_err}"}
    except Exception as e:
        print(f"General error generating login tips: {e}")
        return {"success": False, "message": f"Failed to generate tips: {e}"}

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

# --- New: Handle Google Authentication Backend ---
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
        # 1. Verify the Google ID token
        # This verifies the token's signature and extracts its claims.
        # The 'check_revoked=True' ensures the token hasn't been revoked.
        decoded_token = auth.verify_id_token(id_token, check_revoked=True)
        uid = decoded_token['uid']
        print(f"Google ID Token verified for UID: {uid}")

        # 2. Check if a user with this UID or email already exists in Firebase Auth
        try:
            user = auth.get_user(uid)
            print(f"User with UID {uid} already exists in Firebase Auth.")
            # If user exists, ensure their profile is up-to-date
            USER_PROFILES_COLLECTION.document(uid).update({
                'name': display_name or user.display_name,
                'email': email or user.email,
                'photoURL': photo_url or user.photo_url,
                'lastLogin': firestore.SERVER_TIMESTAMP,
                'authProvider': 'google' # Update provider if it was different
            })
            return {"success": True, "message": "Successfully signed in with Google."}
        except auth.UserNotFoundError:
            # User does not exist with this UID, check by email
            try:
                user_by_email = auth.get_user_by_email(email)
                print(f"User with email {email} already exists but different UID. Attempting to link.")
                # If a user with this email exists but was created via another provider (e.g., password),
                # you might want to link the Google account to it. This is more complex and usually
                # handled on the client-side with re-authentication.
                # For simplicity here, we'll just sign them in if their UID matches,
                # otherwise, we'll indicate an existing account.
                # If the user_by_email's UID is different, it means they have an existing account
                # with the same email but through a different sign-in method.
                # Firebase Admin SDK doesn't directly "link" accounts in this scenario without
                # client-side re-authentication.
                # A common approach is to prevent new Google sign-ups if email exists with another provider
                # or require linking on the client. For now, we'll treat this as a conflict.
                return {"success": False, "message": "An account with this email already exists using a different sign-in method. Please use that method to log in."}

            except auth.UserNotFoundError:
                # No user with this UID or email found, create a new one
                print(f"Creating new user for Google sign-in: {email}")
                user = auth.create_user(
                    uid=uid, # Use the UID from the Google token
                    email=email,
                    display_name=display_name,
                    photo_url=photo_url,
                    email_verified=decoded_token.get('email_verified', False) # Use email_verified from token
                )
                print(f"New Firebase Auth user created for Google: {user.uid}")

                # Create user profile in Firestore
                USER_PROFILES_COLLECTION.document(user.uid).set({
                    'name': display_name,
                    'username': email.split('@')[0], # Use email prefix as username for Google users
                    'email': email,
                    'photoURL': photo_url,
                    'createdAt': firestore.SERVER_TIMESTAMP,
                    'emailVerified': decoded_token.get('email_verified', False),
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

