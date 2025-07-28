import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
from dotenv import load_dotenv
import json
import sys # <--- ADD THIS LINE

load_dotenv()

# --- Configuration ---
# All sensitive IDs and keys should be loaded from environment variables
APP_ID = os.getenv("FIREBASE_PROJECT_ID") # Load APP_ID from env variable

# --- Firebase Client-Side Config (for Frontend JS/SDK) ---
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
        # Changed print to sys.stderr for better visibility in Render logs
        print(f"WARNING: Firebase client config missing environment variable for {key}. Please set it.", file=sys.stderr)


# --- Firebase Admin SDK Initialization ---
def initialize_firebase():
    """Initializes the Firebase Admin SDK using environment variable."""
    if not firebase_admin._apps:
        try:
            firebase_json = os.getenv("FIREBASE_CREDENTIAL_JSON")

            # --- ADD THESE DEBUGGING LINES HERE ---
            print(f"DEBUG: Value of FIREBASE_CREDENTIAL_JSON (first 100 chars): {firebase_json[:100] if firebase_json else 'None'}...", file=sys.stderr)
            print(f"DEBUG: Length of FIREBASE_CREDENTIAL_JSON: {len(firebase_json) if firebase_json else 0}", file=sys.stderr)
            if firebase_json and "\\n" in firebase_json:
                print("DEBUG: '\\n' found in FIREBASE_CREDENTIAL_JSON string (this is good).", file=sys.stderr)
            else:
                print("DEBUG: '\\n' NOT found in FIREBASE_CREDENTIAL_JSON string (this is bad for private key).", file=sys.stderr)
            # --- END DEBUGGING LINES ---

            if not firebase_json:
                raise ValueError("FIREBASE_CREDENTIAL_JSON environment variable is missing.")

            # Convert JSON string to dict
            cred_dict = json.loads(firebase_json)
            cred = credentials.Certificate(cred_dict)

            # Initialize Firebase Admin SDK with the storageBucket
            firebase_admin.initialize_app(cred, {
                'storageBucket': FIREBASE_CLIENT_CONFIG["storageBucket"]
            })
            print("Firebase Admin SDK initialized successfully with Storage Bucket.", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to decode JSON from FIREBASE_CREDENTIAL_JSON: {e}", file=sys.stderr)
            # Print more of the problematic JSON string to help identify issues
            print(f"ERROR: Faulty JSON start (first 500 chars): {firebase_json[:500] if firebase_json else 'N/A'}", file=sys.stderr)
            raise  # Re-raise to stop app if JSON is malformed
        except ValueError as e:
            print(f"ERROR: Error initializing Firebase with certificate: {e}", file=sys.stderr)
            raise  # Re-raise if cert is invalid
        except Exception as e:
            print(f"ERROR: An unexpected error occurred during Firebase initialization: {e}", file=sys.stderr)
            raise

# Initialize Firebase when this module is imported
initialize_firebase()

# --- Firestore ---
db = firestore.client()

# --- Firestore Collection References ---
UNIQUE_USERNAMES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/usernames')
USER_PROFILES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/user_profiles')
FEEDBACK_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/feedback')
EMAIL_OTPS_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/email_otps')

# Aliases for convenience (if used elsewhere)
UNIQUE_USERNAMES_COL = UNIQUE_USERNAMES_COLLECTION
USER_PROFILES_COL = USER_PROFILES_COLLECTION
FEEDBACK_COL = FEEDBACK_COLLECTION
EMAIL_OTPS_COL = EMAIL_OTPS_COLLECTION
