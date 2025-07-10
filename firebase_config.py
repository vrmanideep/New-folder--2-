# firebase_config.py

import firebase_admin
from firebase_admin import credentials, auth, firestore
import os

# --- Configuration ---
# IMPORTANT: Replace with the actual path to your Firebase service account key JSON file.
SERVICE_ACCOUNT_KEY_PATH = os.getenv('FIREBASE_SERVICE_ACCOUNT_KEY_PATH', r"C:\Users\manid\OneDrive\Desktop\New folder (2)\project-c6a71-firebase-adminsdk-fbsvc-bcede94ae2.json")

# Define your application ID for Firestore collection paths.
# This should match the APP_ID used in your Firestore Security Rules.
# Ensure this matches your actual Firebase Project ID!
APP_ID = "project-c6a71" # <--- VERIFY THIS MATCHES YOUR FIREBASE PROJECT ID

# --- Firebase Admin SDK Initialization ---
def initialize_firebase():
    """Initializes the Firebase Admin SDK."""
    if not firebase_admin._apps:
        try:
            cred = credentials.Certificate(SERVICE_ACCOUNT_KEY_PATH)
            firebase_admin.initialize_app(cred)
            print("Firebase Admin SDK initialized successfully.")
        except Exception as e:
            print(f"Error initializing Firebase Admin SDK: {e}")
            raise # Re-raise the exception to stop execution if initialization fails

# Initialize Firebase when this module is imported
initialize_firebase()

# Get Firebase service clients
db = firestore.client()

# --- Firestore Collection References ---
UNIQUE_USERNAMES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/unique_usernames')
USER_PROFILES_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/user_profiles')
EMAIL_OTPS_COLLECTION = db.collection(f'artifacts/{APP_ID}/public/data/email_otps')

# --- Firebase Client-Side Configuration (for Frontend) ---
# You can find this in your Firebase Console -> Project settings -> General -> Your apps -> Web app -> Config
# REPLACE ALL PLACEHOLDER VALUES WITH YOUR ACTUAL CONFIGURATION!

FIREBASE_CLIENT_CONFIG = {
    "apiKey": "AIzaSyDMihwTLdN8pY1W0gxNacErV4u6PsLtT44",
    "authDomain": "project-c6a71.firebaseapp.com",
    "projectId": "project-c6a71",
    "storageBucket": "project-c6a71.firebasestorage.app",
    "messagingSenderId": "678029237088",
    "appId": "1:678029237088:web:d0f4a93521c92dcb2cdc05"
}
