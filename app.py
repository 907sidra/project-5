import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Memory-based Storage ---
stored_data = {}
failed_attempts = {}
session_state = st.session_state

# --- Generate a Static Key (not best practice, but okay for in-memory demo) ---
if "fernet_key" not in session_state:
    session_state.fernet_key = Fernet.generate_key()
    session_state.fernet = Fernet(session_state.fernet_key)

# --- Reauthorization Flag ---
if "reauth_required" not in session_state:
    session_state.reauth_required = False

# --- Simple Login for Reauthorization ---
def login():
    st.title("🔐 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            session_state.reauth_required = False
            for user in failed_attempts:
                failed_attempts[user] = 0
            st.success("Reauthorized. You can now retrieve data.")
        else:
            st.error("Invalid login credentials.")

# --- Hash Function ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Store Data ---
def store_data_page():
    st.title("📥 Store New Data")
    username = st.text_input("Enter a unique data name (e.g., user1_data)")
    text = st.text_area("Enter the text to store securely")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Store Securely"):
        if username in stored_data:
            st.warning("That username already exists. Choose a unique one.")
            return
        if text and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = session_state.fernet.encrypt(text.encode()).decode()
            stored_data[username] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            failed_attempts[username] = 0
            st.success(f"Data stored securely under key '{username}'")
        else:
            st.error("Please fill in all fields.")

# --- Retrieve Data ---
def retrieve_data_page():
    st.title("🔓 Retrieve Stored Data")
    username = st.text_input("Enter your data name (e.g., user1_data)")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Retrieve Data"):
        if username not in stored_data:
            st.error("No data found with this name.")
            return

        if session_state.reauth_required:
            st.warning("Too many failed attempts. Please reauthorize.")
            return

        hashed_input = hash_passkey(passkey)
        stored_hashed_passkey = stored_data[username]["passkey"]

        if hashed_input == stored_hashed_passkey:
            decrypted = session_state.fernet.decrypt(
                stored_data[username]["encrypted_text"].encode()
            ).decode()
            st.success("✅ Data Retrieved Successfully:")
            st.code(decrypted)
            failed_attempts[username] = 0  # Reset
        else:
            failed_attempts[username] += 1
            st.error(f"❌ Incorrect passkey. Attempts: {failed_attempts[username]}/3")
            if failed_attempts[username] >= 3:
                session_state.reauth_required = True

# --- Home Page ---
def home_page():
    st.title("🔐 Secure Data Storage System")
    st.markdown("Choose an action:")
    action = st.selectbox("Select Option", ["Store New Data", "Retrieve Data"])

    if action == "Store New Data":
        store_data_page()
    elif action == "Retrieve Data":
        retrieve_data_page()

# --- Main App Logic ---
def main():
    st.sidebar.title("🔍 Navigation")
    if session_state.reauth_required:
        login()
    else:
        page = st.sidebar.radio("Go to", ["Home", "Store", "Retrieve", "Login"])
        if page == "Home":
            home_page()
        elif page == "Store":
            store_data_page()
        elif page == "Retrieve":
            retrieve_data_page()
        elif page == "Login":
            login()

if __name__ == "__main__":
    main()

