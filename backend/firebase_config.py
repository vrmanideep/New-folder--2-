import firebase_admin
from firebase_admin import credentials, auth, firestore
import os
from dotenv import load_dotenv
import json
import sys
import base64 # <--- ADDED THIS LINE FOR BASE64 DECODING

load_dotenv()

# --- Configuration ---
# All sensitive IDs and keys should be loaded from environment variables
# APP_ID will be updated from the credential dictionary after initialization
APP_ID = os.getenv("FIREBASE_PROJECT_ID")

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
        print(f"WARNING: Firebase client config missing environment variable for {key}. Please set it.", file=sys.stderr)


# --- Firebase Admin SDK Initialization ---
def initialize_firebase():
    """Initializes the Firebase Admin SDK using environment variable."""
    global APP_ID # Declare global to modify APP_ID

    if not firebase_admin._apps:
        try:
            # --- MODIFIED THESE LINES TO READ AND DECODE BASE64 ---
            firebase_json_b64 = os.getenv("FIREBASE_CREDENTIAL_B64")
            if not firebase_json_b64:
                raise ValueError("FIREBASE_CREDENTIAL_B64 environment variable is missing.")

            # Decode the base64 string back to a JSON string
            decoded_json_bytes = base64.b64decode(firebase_json_b64)
            firebase_json_string = decoded_json_bytes.decode('utf-8')

            # Debugging decoded string (optional, can be removed later)
            print(f"DEBUG: Decoded JSON string (first 100 chars): {firebase_json_string[:100]}...", file=sys.stderr)
            print(f"DEBUG: Length of Decoded JSON string: {len(firebase_json_string)}", file=sys.stderr)
            if "\\n" in firebase_json_string:
                print("DEBUG: '\\n' found in decoded JSON string (this is good).", file=sys.stderr)
            else:
                print("DEBUG: '\\n' NOT found in decoded JSON string (this is bad for private key).", file=sys.stderr)

            # Convert JSON string to dict
            cred_dict = json.loads(firebase_json_string)
            # --- END OF MODIFIED LINES ---

            cred = credentials.Certificate(cred_dict)

            # Initialize Firebase Admin SDK with the storageBucket
            firebase_admin.initialize_app(cred, {
                'storageBucket': FIREBASE_CLIENT_CONFIG["storageBucket"]
            })
            print("Firebase Admin SDK initialized successfully with Storage Bucket.", file=sys.stderr)

            # Update APP_ID from the credentials dictionary for consistency
            APP_ID = cred_dict.get('project_id', APP_ID)

        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to decode JSON from FIREBASE_CREDENTIAL_B64 (after base64 decode): {e}", file=sys.stderr)
            print(f"ERROR: Problematic string start (first 500 chars after b64 decode): {firebase_json_string[:500] if 'firebase_json_string' in locals() else 'N/A'}", file=sys.stderr)
            raise
        except ValueError as e:
            print(f"ERROR: Error initializing Firebase with certificate: {e}", file=sys.stderr)
            raise
        except Exception as e:
            print(f"ERROR: An unexpected error occurred during Firebase initialization: {e}", file=sys.stderr)
            raise

# Initialize Firebase when this module is imported
initialize_firebase()

# --- Firestore ---
db = firestore.client()

# --- Firestore Collection References ---
# These will now use the APP_ID that was potentially updated from the credentials
UNIQUE_USERNAMES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/usernames')
USER_PROFILES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/user_profiles')
FEEDBACK_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/feedback')
EMAIL_OTPS_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/email_otps')

# Aliases for convenience (if used elsewhere)
UNIQUE_USERNAMES_COL = UNIQUE_USERNAMES_COLLECTION
USER_PROFILES_COL = USER_PROFILES_COLLECTION
FEEDBACK_COL = FEEDBACK_COLLECTION
EMAIL_OTPS_COL = EMAIL_OTPS_COLLECTION
