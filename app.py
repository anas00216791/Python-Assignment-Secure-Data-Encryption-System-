import streamlit as st
from cryptography.fernet import Fernet

# ---------- Helper Functions ----------
def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

# ---------- Streamlit App ----------
st.set_page_config(page_title="Secure Data Encryption", layout="centered")
st.title("🔐 Secure Data Encryption System")

st.sidebar.header("Encryption Settings")
method = st.sidebar.selectbox("Choose Encryption Method", ["Fernet (AES-based)"])
key_option = st.sidebar.radio("Key Options", ["Generate New Key", "Use Existing Key"])

if key_option == "Generate New Key":
    key = generate_key()
    st.sidebar.success("New Key Generated")
else:
    key = st.sidebar.text_input("Enter your key", type="password").encode()

st.sidebar.write("🔑 Key (save it safely):")
st.sidebar.code(key.decode(), language="text")

# User Input
text = st.text_area("Enter Text to Encrypt or Decrypt", height=150)

col1, col2 = st.columns(2)
with col1:
    if st.button("Encrypt"):
        if not text:
            st.warning("Please enter some text to encrypt.")
        else:
            try:
                encrypted = encrypt_message(text, key)
                st.success("Encrypted Message:")
                st.code(encrypted.decode(), language="text")
            except Exception as e:
                st.error(f"Encryption failed: {e}")

with col2:
    if st.button("Decrypt"):
        if not text:
            st.warning("Please enter some encrypted text to decrypt.")
        else:
            try:
                decrypted = decrypt_message(text.encode(), key)
                st.success("Decrypted Message:")
                st.code(decrypted, language="text")
            except Exception as e:
                st.error(f"Decryption failed: {e}")
