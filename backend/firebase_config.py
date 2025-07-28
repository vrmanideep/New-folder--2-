# backend/firebase_config.py

import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
from dotenv import load_dotenv
import json

load_dotenv() # Load variables from .env into os.environ

# --- Configuration ---
# All sensitive IDs and keys should be loaded from environment variables
APP_ID = os.getenv("FIREBASE_PROJECT_ID") # Load APP_ID from env variable

# --- Firebase Client-Side Config (for Frontend JS/SDK) ---
# This config is also used to get the storageBucket for Admin SDK initialization
FIREBASE_CLIENT_CONFIG = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID")
}

# Validate that essential client config values are present
for key, value in FIREBASE_CLIENT_CONFIG.items():
    if not value:
        print(f"WARNING: Firebase client config missing environment variable for {key}. Please set it.")
        # For deployment, you might want to raise an error here instead of just printing a warning
        # raise ValueError(f"Missing Firebase client config environment variable: FIREBASE_{key.upper()}")


# --- Firebase Admin SDK Initialization ---
def initialize_firebase():
    """Initializes the Firebase Admin SDK using environment variable."""
    if not firebase_admin._apps:
        try:
            firebase_json = os.getenv("FIREBASE_CREDENTIAL_JSON")
            if not firebase_json:
                raise ValueError("FIREBASE_CREDENTIAL_JSON environment variable is missing.")

            # Convert JSON string to dict
            cred_dict = json.loads(firebase_json)
            cred = credentials.Certificate(cred_dict)

            # Initialize Firebase Admin SDK with the storageBucket
            # The storageBucket is needed for Firebase Storage operations
            firebase_admin.initialize_app(cred, {
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
UNIQUE_USERNAMES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/usernames')
USER_PROFILES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/user_profiles')
FEEDBACK_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/feedback') # Ensure this is defined
EMAIL_OTPS_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/email_otps') # If still used

# Aliases for convenience (if used elsewhere)
UNIQUE_USERNAMES_COL = UNIQUE_USERNAMES_COLLECTION
USER_PROFILES_COL = USER_PROFILES_COLLECTION
FEEDBACK_COL = FEEDBACK_COLLECTION
EMAIL_OTPS_COL = EMAIL_OTPS_COLLECTION
