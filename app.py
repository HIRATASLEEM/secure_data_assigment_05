import streamlit as st
from cryptography.fernet import Fernet
import base64

# --- Initialize session state ---
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# --- Helper functions ---
def generate_key(passkey: str) -> bytes:
    """Generates a Fernet key from a passkey"""
    key = base64.urlsafe_b64encode(passkey.zfill(32).encode())
    return key

def encrypt_data(data: str, passkey: str) -> str:
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, passkey: str) -> str:
    try:
        key = generate_key(passkey)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return None

# --- Page Navigation ---
st.sidebar.title("🔐 Secure Storage App")
page = st.sidebar.radio("Go to", ["Home", "Insert Data", "Retrieve Data", "Login"])

# --- Login Page ---
if page == "Login":
    st.title("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "1234":
            st.success("Login successful.")
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
        else:
            st.error("Login failed.")

# --- Home Page ---
elif page == "Home":
    st.title("🏠 Home - Secure Data Storage")
    st.markdown("Choose an option from the sidebar:\n- 🔐 Insert new data\n- 🔓 Retrieve your data")

# --- Insert Data Page ---
elif page == "Insert Data":
    if st.session_state.authorized:
        st.title("📝 Insert Data")
        text = st.text_area("Enter data to store:")
        passkey = st.text_input("Enter a unique passkey:", type="password")

        if st.button("🔒 Encrypt & Store"):
            if text and passkey:
                encrypted = encrypt_data(text, passkey)
                st.session_state.data_store[passkey] = encrypted
                st.success("Data securely stored!")
            else:
                st.warning("Please fill in both fields.")
    else:
        st.warning("🔒 You must login to access this page.")

# --- Retrieve Data Page ---
elif page == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("⚠️ Too many failed attempts. Please login again.")
        st.stop()

    st.title("🔓 Retrieve Data")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Unlock"):
        encrypted_data = st.session_state.data_store.get(passkey)
        if encrypted_data:
            decrypted = decrypt_data(encrypted_data, passkey)
            if decrypted:
                st.success("✅ Decrypted Data:")
                st.code(decrypted)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ Incorrect passkey.")
        else:
            st.session_state.failed_attempts += 1
            st.error("❌ No data found for this passkey.")

    st.markdown(f"❗ Failed Attempts: **{st.session_state.failed_attempts}/3**")
    if st.session_state.failed_attempts >= 3:
        st.session_state.authorized = False
        st.warning("⚠️ Too many failed attempts! Redirecting to login.")
