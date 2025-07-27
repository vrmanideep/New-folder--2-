# backend/firebase_config.py

import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
from dotenv import load_dotenv

load_dotenv() # This will load variables from .env into os.environ
import json

# --- Configuration ---
APP_ID = "project-c6a71"   # <--- VERIFY THIS MATCHES YOUR FIREBASE PROJECT ID

# --- Firebase Client-Side Config (for Frontend JS/SDK) ---
# This config is also used to get the storageBucket for Admin SDK initialization
FIREBASE_CLIENT_CONFIG = {
    "apiKey": "AIzaSyDMihwTLdN8pY1W0gxNacErV4u6PsLtT44",
    "authDomain": "project-c6a71.firebaseapp.com",
    "projectId": "project-c6a71",
    "storageBucket": "project-c6a71.appspot.com", # <--- UPDATED: Using your confirmed bucket name
    "messagingSenderId": "678029237088",
    "appId": "1:678029237088:web:d0f4a93521c92dcb2cdc05"
}


# --- Firebase Admin SDK Initialization ---
def initialize_firebase():
    """Initializes the Firebase Admin SDK using environment variable."""
    if not firebase_admin._apps:
        try:
            firebase_json = os.environ.get("FIREBASE_CREDENTIAL_JSON")
            if not firebase_json:
                raise ValueError("FIREBASE_CREDENTIAL_JSON environment variable is missing.")

            # Convert JSON string to dict
            cred_dict = json.loads(firebase_json)
            cred = credentials.Certificate(cred_dict)

            # Initialize Firebase Admin SDK with the storageBucket
            # The storageBucket is needed for Firebase Storage operations
            firebase_admin.initialize_app(cred, { # Corrected: initialize_app (lowercase 'a')
                'storageBucket': FIREBASE_CLIENT_CONFIG["storageBucket"]
            })
            print("Firebase Admin SDK initialized successfully with Storage Bucket.")
        except Exception as e:
            print(f"Error initializing Firebase Admin SDK: {e}")
            raise  # Re-raise to stop app if init fails

# Initialize Firebase when this module is imported
initialize_firebase()

# --- Firestore ---
db = firestore.client()

# --- Firestore Collection References ---
# Note: The collection names here should match what your backend uses for consistency.
# I've kept them as they were in your auth_service.py.
UNIQUE_USERNAMES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/usernames') # Corrected: 'usernames'
USER_PROFILES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/user_profiles')
# EMAIL_OTPS_COLLECTION is no longer directly used for email verification, but kept if other OTP flows exist
EMAIL_OTPS_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/email_otps')

# Aliases for convenience (if used elsewhere)
UNIQUE_USERNAMES_COL = UNIQUE_USERNAMES_COLLECTION
USER_PROFILES_COL = USER_PROFILES_COLLECTION
EMAIL_OTPS_COL = EMAIL_OTPS_COLLECTION
