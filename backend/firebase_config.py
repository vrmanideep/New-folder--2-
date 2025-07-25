# firebase_config.py

import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
import json

# --- Configuration ---
APP_ID = "project-c6a71"  # <--- VERIFY THIS MATCHES YOUR FIREBASE PROJECT ID

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
            firebase_admin.initialize_app(cred)
            print("Firebase Admin SDK initialized successfully.")
        except Exception as e:
            print(f"Error initializing Firebase Admin SDK: {e}")
            raise  # Re-raise to stop app if init fails

# Initialize Firebase when this module is imported
initialize_firebase()

# --- Firestore ---
db = firestore.client()

# --- Firestore Collection References ---
UNIQUE_USERNAMES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/unique_usernames')
USER_PROFILES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/user_profiles')
EMAIL_OTPS_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/email_otps')

UNIQUE_USERNAMES_COL = UNIQUE_USERNAMES_COLLECTION
USER_PROFILES_COL = USER_PROFILES_COLLECTION
EMAIL_OTPS_COL = EMAIL_OTPS_COLLECTION

# --- Firebase Client-Side Config (for Frontend JS/SDK) ---
FIREBASE_CLIENT_CONFIG = {
    "apiKey": "AIzaSyDMihwTLdN8pY1W0gxNacErV4u6PsLtT44",
    "authDomain": "project-c6a71.firebaseapp.com",
    "projectId": "project-c6a71",
    "storageBucket": "project-c6a71.firebasestorage.app",
    "messagingSenderId": "678029237088",
    "appId": "1:678029237088:web:d0f4a93521c92dcb2cdc05"
}
