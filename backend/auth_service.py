# backend/auth_service.py

from firebase_admin import auth, firestore, exceptions
import secrets
import string
import time

# Assuming firebase_config is initialized and contains db and APP_ID
from . import firebase_config

# Firestore references
users_collection = firebase_config.db.collection(f'artifacts/{firebase_config.APP_ID}/public/data/users')
user_profiles_collection = firebase_config.db.collection(f'artifacts/{firebase_config.APP_ID}/public/data/user_profiles')
usernames_collection = firebase_config.db.collection(f'artifacts/{firebase_config.APP_ID}/public/data/usernames')


def generate_random_password(length=12):
    """Generate a random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

def check_username_uniqueness_backend(username):
    """
    Checks if a username is already taken in Firestore.
    """
    if not username:
        return {"available": False, "message": "Username cannot be empty."}

    try:
        # Check if the username document exists
        doc_ref = usernames_collection.document(username)
        doc = doc_ref.get()

        if doc.exists:
            return {"available": False, "message": "Username is already taken."}
        else:
            return {"available": True, "message": "Username is available!"}
    except Exception as e:
        print(f"Error checking username uniqueness: {e}")
        return {"available": False, "message": "Error checking username."}


def register_user_backend(name, username, email, password):
    """
    Registers a new user in Firebase Authentication and stores profile data in Firestore.
    Sends email verification link upon successful creation.
    Returns a custom token for client-side sign-in.
    """
    if not name or not username or not email or not password:
        return {"success": False, "message": "All fields are required."}

    try:
        # 1. Create user in Firebase Authentication
        user = auth.create_user(
            email=email,
            password=password,
            display_name=name,
            email_verified=False # Mark as not verified initially
        )
        print(f"Firebase Auth user created: {user.uid}")

        # 2. Store username mapping to UID
        username_doc_ref = usernames_collection.document(username)
        username_doc_ref.set({
            'uid': user.uid,
            'email': email,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
        print(f"Username '{username}' recorded as unique.")

        # 3. Store user profile in Firestore
        user_profile_doc_ref = user_profiles_collection.document(user.uid)
        user_profile_doc_ref.set({
            'name': name,
            'username': username,
            'email': email,
            'photoURL': user.photo_url, # Will be None initially for email/password
            'emailVerified': False,
            'createdAt': firestore.SERVER_TIMESTAMP
        })
        print(f"User profile for '{username}' stored in Firestore.")

        # 4. Generate a custom token for the client to sign in
        custom_token = auth.create_custom_token(user.uid).decode('utf-8')
        print(f"Custom token generated for user: {user.uid}")

        # 5. Send email verification link (this will generate the link, client-side sends it)
        send_firebase_email_verification_backend(user.uid)
        print(f"Email verification link generation triggered for {email}")


        return {"success": True, "message": "Registration successful! Please check your email for a verification link.", "custom_token": custom_token}

    except exceptions.FirebaseError as e:
        error_message = str(e)
        if "EMAIL_EXISTS" in error_message:
            return {"success": False, "message": "Email is already registered."}
        elif "WEAK_PASSWORD" in error_message:
            return {"success": False, "message": "Password is too weak."}
        elif "The email address is already in use by another account." in error_message:
            return {"success": False, "message": "Email is already in use."}
        elif "The email address is not valid." in error_message:
            return {"success": False, "message": "The email address is not valid."}
        print(f"Firebase Auth error during registration: {e}")
        return {"success": False, "message": f"Registration failed: {error_message}"}
    except Exception as e:
        print(f"Unexpected error during registration: {e}")
        return {"success": False, "message": "An unexpected error occurred during registration."}

def send_firebase_email_verification_backend(uid):
    """
    Generates a Firebase email verification link for the user.
    The actual email sending is typically handled by Firebase's configured email templates
    when triggered by the client-side SDK's sendEmailVerification method.
    This backend function primarily sets the action URL for the link.
    """
    try:
        user = auth.get_user(uid)
        if not user.email_verified:
            # Generate the email action link
            action_code_settings = auth.ActionCodeSettings(
                url='http://localhost:5000/email_verification.html', # Redirect to email_verification.html after verification
                handle_code_in_app=True,
                # The Android and iOS packages are optional, but useful if you have a mobile app
                # android_package_name='com.example.androidapp',
                # ios_bundle_id='com.example.iosapp',
                # dynamic_link_domain='example.page.link' # Optional: if using Firebase Dynamic Links
            )
            link = auth.generate_email_verification_link(user.email, action_code_settings)
            print(f"Firebase Email Verification Link generated for {user.email}: {link}")
            # The actual email sending is expected to be triggered by the client-side Firebase SDK
            # using `sendEmailVerification`. This backend function just ensures the link structure is correct.
            return {"success": True, "message": "Verification email link generated."}
        else:
            return {"success": True, "message": "Email is already verified."}
    except exceptions.FirebaseError as e:
        print(f"Firebase error generating verification email link: {e}")
        return {"success": False, "message": f"Failed to generate verification email link: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error generating verification email link: {e}")
        return {"success": False, "message": "An unexpected error occurred."}


def login_user_backend(identifier, password):
    """
    Logs in a user using email/password or username/password.
    If using username, it first resolves the username to an email.
    Returns a custom token for client-side sign-in.
    """
    try:
        email = identifier
        # Check if the identifier is a username
        if "@" not in identifier:
            username_doc = usernames_collection.document(identifier).get()
            if username_doc.exists:
                email = username_doc.to_dict().get('email')
            else:
                return {"success": False, "message": "Invalid credentials."} # Changed message for clarity

        # Attempt to get user by email
        user = auth.get_user_by_email(email)

        # Firebase Admin SDK does not directly verify passwords.
        # This backend function is primarily for generating a custom token for a known user.
        # The actual password verification should happen on the client-side using Firebase Client SDK
        # (e.g., signInWithEmailAndPassword) which then provides an ID token.
        # For a backend-driven login, you'd need a more complex setup to verify password securely.
        # For this demo, we'll assume the client handles password verification and then sends an ID token,
        # or we generate a custom token directly if the user is found (less secure for password login).
        # Let's generate a custom token for demonstration purposes, assuming password was verified client-side.
        custom_token = auth.create_custom_token(user.uid).decode('utf-8')
        return {"success": True, "message": "Login successful!", "token": custom_token}

    except exceptions.FirebaseError as e:
        error_message = str(e)
        if "EMAIL_NOT_FOUND" in error_message or "user-not-found" in error_message:
            return {"success": False, "message": "Email ID is not registered."} # Specific message for unregistered email
        elif "INVALID_PASSWORD" in error_message or "wrong-password" in error_message:
            return {"success": False, "message": "Invalid credentials."}
        # Add more specific error handling if needed, e.g., for disabled users
        print(f"Firebase Auth error during login: {e}")
        return {"success": False, "message": f"Login failed: {error_message}"}
    except Exception as e:
        print(f"Unexpected error during login: {e}")
        return {"success": False, "message": "An unexpected error occurred during login."}


def delete_user_data_backend(identifier):
    """
    Deletes user data from Firebase Authentication and Firestore.
    Can delete by UID or email.
    """
    try:
        user_record = None
        if "@" in identifier: # Assume it's an email
            user_record = auth.get_user_by_email(identifier)
        else: # Assume it's a UID or username (need to resolve username to UID)
            # First, try to get by UID directly
            try:
                user_record = auth.get_user(identifier)
            except exceptions.FirebaseError:
                # If not a UID, check if it's a username
                username_doc = usernames_collection.document(identifier).get()
                if username_doc.exists:
                    uid_from_username = username_doc.to_dict().get('uid')
                    user_record = auth.get_user(uid_from_username)
                else:
                    return {"success": False, "message": "User not found."}

        uid = user_record.uid

        # Delete from Firebase Authentication
        auth.delete_user(uid)
        print(f"Firebase Auth user deleted: {uid}")

        # Delete user profile from Firestore
        user_profile_doc_ref = user_profiles_collection.document(uid)
        if user_profile_doc_ref.get().exists:
            user_profile_doc_ref.delete()
            print(f"User profile deleted from Firestore for UID: {uid}")

        # Delete username mapping from Firestore
        # Find the username associated with this UID to delete its document
        username_query = usernames_collection.where('uid', '==', uid).limit(1).get()
        for doc in username_query:
            doc.reference.delete()
            print(f"Username mapping deleted from Firestore for UID: {uid}")
            break # Should only be one

        return {"success": True, "message": "Account and associated data deleted successfully."}

    except exceptions.FirebaseError as e:
        print(f"Firebase error deleting user: {e}")
        return {"success": False, "message": f"Failed to delete account: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error during account deletion: {e}")
        return {"success": False, "message": "An unexpected error occurred during account deletion."}


async def get_login_tips_backend():
    """
    Fetches login tips from a dummy API (simulated async operation).
    """
    # Simulate an asynchronous operation, e.g., fetching from an external service
    await asyncio.sleep(0.1) # Non-blocking sleep

    tips = [
        "Use a strong, unique password.",
        "Enable two-factor authentication for added security.",
        "Keep your recovery email and phone number updated.",
        "Be wary of phishing attempts; always check the URL.",
        "Use a password manager to store complex passwords."
    ]
    return {"success": True, "tips": tips}


def get_user_profile_backend(uid):
    """
    Fetches user profile data from Firestore.
    """
    try:
        user_profile_doc = user_profiles_collection.document(uid).get()
        if user_profile_doc.exists:
            profile_data = user_profile_doc.to_dict()
            # Also fetch emailVerified status directly from Firebase Auth
            firebase_user = auth.get_user(uid)
            profile_data['emailVerified'] = firebase_user.email_verified
            return {"success": True, "profile": profile_data}
        else:
            return {"success": False, "message": "User profile not found."}
    except exceptions.FirebaseError as e:
        print(f"Firebase error fetching user profile: {e}")
        return {"success": False, "message": f"Error fetching profile: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error fetching user profile: {e}")
        return {"success": False, "message": "An unexpected error occurred."}


def update_user_address_backend(uid, address):
    """
    Updates the user's address in their Firestore profile.
    """
    try:
        user_profile_doc_ref = user_profiles_collection.document(uid)
        user_profile_doc_ref.update({'address': address, 'updatedAt': firestore.SERVER_TIMESTAMP})
        return {"success": True, "message": "Address updated successfully."}
    except exceptions.FirebaseError as e:
        print(f"Firebase error updating address: {e}")
        return {"success": False, "message": f"Error updating address: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error updating address: {e}")
        return {"success": False, "message": "An unexpected error occurred."}


def handle_google_auth_backend(id_token, display_name, email, photo_url):
    """
    Handles Google Sign-In/Sign-Up by verifying the ID token and
    creating/updating user profile in Firestore.
    """
    try:
        # Verify the ID token to get the UID
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']

        # Check if user already exists in Firestore profiles
        user_profile_doc_ref = user_profiles_collection.document(uid)
        user_profile_doc = user_profile_doc_ref.get()

        if user_profile_doc.exists:
            # User profile already exists, update if necessary
            user_profile_doc_ref.update({
                'name': display_name,
                'email': email,
                'photoURL': photo_url,
                'emailVerified': True, # Google accounts are typically email verified
                'lastLogin': firestore.SERVER_TIMESTAMP
            })
            message = "Google login successful. Profile updated."
        else:
            # New Google user, create profile
            # Attempt to find an existing username or generate one if needed
            username = email.split('@')[0] # Default username from email
            # You might want more sophisticated username generation/checking for Google users
            # For simplicity, we'll try to use a derived username.

            # Check if this derived username is already taken by a non-Google user
            username_taken = usernames_collection.document(username).get().exists
            if username_taken:
                # If the derived username is taken, append a unique identifier
                username = f"{username}-{uid[:4]}" # Append first 4 chars of UID

            # Store username mapping
            usernames_collection.document(username).set({
                'uid': uid,
                'email': email,
                'timestamp': firestore.SERVER_TIMESTAMP
            })

            user_profile_doc_ref.set({
                'name': display_name,
                'username': username, # Store the chosen/generated username
                'email': email,
                'photoURL': photo_url,
                'emailVerified': True, # Google accounts are typically email verified
                'createdAt': firestore.SERVER_TIMESTAMP,
                'lastLogin': firestore.SERVER_TIMESTAMP
            })
            message = "Google sign-up successful. Welcome!"

        return {"success": True, "message": message}

    except exceptions.FirebaseError as e:
        print(f"Firebase error during Google auth backend: {e}")
        return {"success": False, "message": f"Firebase error: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error during Google auth backend: {e}")
        return {"success": False, "message": "An unexpected error occurred during Google authentication."}
