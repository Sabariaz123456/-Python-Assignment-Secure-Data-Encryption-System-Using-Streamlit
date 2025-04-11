import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Fernet encryption setup
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)

# In-memory storage
stored_data = {}
failed_attempts = {}

# Simple login credentials
AUTHORIZED_USER = "admin"
AUTHORIZED_PASS = "password123"

# ----- Utility Functions -----
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(text):
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt_text(ciphertext):
    return cipher_suite.decrypt(ciphertext.encode()).decode()

def is_authorized():
    return st.session_state.get("authorized", False)

def reset_attempts(username):
    failed_attempts[username] = 0

def increment_attempts(username):
    failed_attempts[username] = failed_attempts.get(username, 0) + 1

def get_attempts(username):
    return failed_attempts.get(username, 0)

# ----- Styling Helper -----
def colored_header(label, emoji):
    st.markdown(f"<h2 style='color:#ff4b4b'>{emoji} {label}</h2>", unsafe_allow_html=True)

def subtext(msg, color="#888"):
    st.markdown(f"<p style='color:{color}; font-size:16px'>{msg}</p>", unsafe_allow_html=True)

# ----- Pages -----

def login_page():
    colored_header("Reauthorization Required", "🔐")
    subtext("Too many failed attempts. Please log in again.")

    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if st.button("Login", use_container_width=True):
        if username == AUTHORIZED_USER and password == AUTHORIZED_PASS:
            st.session_state.authorized = True
            reset_attempts(username)
            st.success("✅ Login successful! You can now retry.")
        else:
            st.error("❌ Invalid credentials. Try again.")

def home_page():
    colored_header("Secure Data Encryption System", "🛡️")
    subtext("Choose an action below:")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📥 Insert New Data", use_container_width=True):
            st.session_state.page = "insert"
    with col2:
        if st.button("🔓 Retrieve Data", use_container_width=True):
            st.session_state.page = "retrieve"

def insert_data_page():
    colored_header("Insert Secure Data", "📝")
    
    username = st.text_input("👤 Username")
    text = st.text_area("🧾 Enter Text to Encrypt")
    passkey = st.text_input("🔐 Set a Secret Passkey", type="password")

    if st.button("🔒 Store Securely", use_container_width=True):
        if username and text and passkey:
            encrypted = encrypt_text(text)
            hashed = hash_passkey(passkey)
            stored_data[username] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data securely stored!")
        else:
            st.error("⚠️ All fields are required.")

    st.markdown("---")
    if st.button("🔙 Back to Home", use_container_width=True):
        st.session_state.page = "home"

def retrieve_data_page():
    colored_header("Retrieve Secure Data", "🔍")

    username = st.text_input("👤 Username")
    passkey = st.text_input("🔑 Enter Passkey", type="password")

    if st.button("🔓 Decrypt Now", use_container_width=True):
        if username in stored_data:
            if get_attempts(username) >= 3 and not is_authorized():
                st.session_state.page = "login"
                return

            hashed_input = hash_passkey(passkey)
            correct_hash = stored_data[username]["passkey"]

            if hashed_input == correct_hash:
                decrypted = decrypt_text(stored_data[username]["encrypted_text"])
                st.success("✅ Decryption Successful!")
                st.code(decrypted, language="text")
                reset_attempts(username)
            else:
                increment_attempts(username)
                attempts_left = 3 - get_attempts(username)
                st.error(f"❌ Incorrect passkey. Attempts left: {max(attempts_left, 0)}")
                if attempts_left <= 0:
                    st.warning("⚠️ Too many failed attempts! Redirecting to login...")
                    st.session_state.page = "login"
        else:
            st.error("⚠️ No data found for that username.")

    st.markdown("---")
    if st.button("🔙 Back to Home", use_container_width=True):
        st.session_state.page = "home"

# ----- Main App -----

st.set_page_config(page_title="Secure Encryptor", page_icon="🛡️", layout="centered")

if "page" not in st.session_state:
    st.session_state.page = "home"

st.markdown(
    "<style>div.block-container{padding-top:2rem;}</style>",
    unsafe_allow_html=True,
)

if st.session_state.page == "home":
    home_page()
elif st.session_state.page == "insert":
    insert_data_page()
elif st.session_state.page == "retrieve":
    retrieve_data_page()
elif st.session_state.page == "login":
    login_page()

