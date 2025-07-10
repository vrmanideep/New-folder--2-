# delete_user_manual.py

# Import necessary modules from your existing backend files
import firebase_config # This will automatically initialize Firebase Admin SDK
from auth_service import delete_user_data_backend

def main():
    """
    Main function to manually delete user data.
    Prompts for an identifier and calls the backend deletion function.
    """
    print("--- Manual User Data Deletion ---")
    print("Enter the email or username of the user you wish to delete.")
    print("This will delete the user from Firebase Authentication,")
    print("their profile from Firestore, and their unique username entry.")
    print("---------------------------------")

    identifier = input("Enter user email or username: ").strip()

    if not identifier:
        print("Error: No identifier provided. Exiting.")
        return

    print(f"\nAttempting to delete user: {identifier}...")
    result = delete_user_data_backend(identifier)

    if result["success"]:
        print(f"SUCCESS: {result['message']}")
    else:
        print(f"FAILURE: {result['message']}")
    print("---------------------------------")

if __name__ == "__main__":
    main()

