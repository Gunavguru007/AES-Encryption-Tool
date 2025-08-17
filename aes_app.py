# aes_tool.py
import streamlit as st
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import binascii

# --- AES Functions ---

def pad_data(data):
    """Pad data to be multiple of 16 bytes using PKCS7."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

def unpad_data(padded_data):
    """Remove PKCS7 padding."""
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    return data

def encrypt_aes(plaintext, key, mode, iv=None):
    """
    Encrypt plaintext using AES in specified mode.
    Returns: encrypted data (Base64 or Hex)
    """
    if mode == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    else:  # CBC
        if iv is None:
            iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    encryptor = cipher.encryptor()
    padded_text = pad_data(plaintext.encode('utf-8'))
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()

    if mode == 'CBC' and iv is not None:
        encrypted_data = iv + ciphertext
    else:
        encrypted_data = ciphertext

    return encrypted_data

def decrypt_aes(encrypted_data, key, mode, iv=None):
    """
    Decrypt data using AES in specified mode.
    Returns: plaintext string
    """
    if mode == 'ECB':
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    else:  # CBC
        if iv is None:
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
        else:
            ciphertext = encrypted_data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad_data(padded_plaintext)
    return plaintext.decode('utf-8')

# --- Custom CSS for Dark Theme & Layout ---
st.set_page_config(page_title="AES Encryption Tool", layout="centered")

# Apply custom CSS
st.markdown("""
<style>
body {
    background-color: #121212;
    color: #e0e0e0;
    font-family: 'Segoe UI', sans-serif;
}
.container {
    background-color: #1e1e1e;
    border-radius: 5px;
    padding: 10px;
    margin-bottom: 15px;
    border: 1px solid #333;
}
h1 {
    color: #007bff;
    text-align: center;
    margin-bottom: 20px;
}
label {
    color: #b3b3b3;
    font-size: 14px;
}
input[type="text"], select, textarea {
    background-color: #2a2a2a;
    color: #ffffff;
    border: 1px solid #444;
    padding: 8px;
    border-radius: 4px;
    width: 100%;
    margin-top: 5px;
    margin-bottom: 10px;
}
button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    margin-right: 10px;
    margin-bottom: 10px;
}
button:hover {
    background-color: #0056b3;
}
button.secondary {
    background-color: #6c757d;
}
button.secondary:hover {
    background-color: #545b62;
}
textarea {
    background-color: #2a2a2a;
    color: #ffffff;
    border: 1px solid #444;
    padding: 10px;
    border-radius: 4px;
    height: 100px;
    width: 100%;
    margin-bottom: 10px;
}
</style>
""", unsafe_allow_html=True)

# --- Title ---
st.markdown("<h1 style='color: #007bff; text-align: center;'>AES Encryption Tool</h1>", unsafe_allow_html=True)

# --- Input Text ---
st.markdown("<div class='container'><strong>Input Text</strong></div>", unsafe_allow_html=True)
input_text = st.text_area("", value="To implement Advanced Encryption Standard (AES) in Python using a cryptographic library, understand block cipher logic, and document the implementation process with screenshots and explanation.", height=100)

# --- Key Section ---
st.markdown("<div class='container'><strong>Encryption Key</strong></div>", unsafe_allow_html=True)

key_size = st.selectbox("Key Size:", [16, 24, 32], index=1)
key_bytes = os.urandom(key_size)

if 'secret_key' not in st.session_state:
    st.session_state.secret_key = base64.b64encode(os.urandom(key_size)).decode('utf-8')
else:
    st.session_state.secret_key = st.text_input("Secret Key (Base64):", value=st.session_state.secret_key, key="key_input")

if st.button("Generate Key"):
    new_key = os.urandom(key_size)
    st.session_state.secret_key = base64.b64encode(new_key).decode('utf-8')

# Decode secret key back to bytes
try:
    key_bytes = base64.b64decode(st.session_state.secret_key)
except Exception:
    st.error("Invalid Base64 key. Please generate or enter a valid one.")
    key_bytes = os.urandom(key_size)

# --- IV Section ---
st.markdown("<div class='container'><strong>Initialization Vector (IV)</strong></div>", unsafe_allow_html=True)

iv_base64 = st.text_input("IV (Base64):", value="", key="iv_input")
if st.button("Generate IV"):
    iv = os.urandom(16)
    iv_base64 = base64.b64encode(iv).decode('utf-8')
    st.session_state.iv = iv_base64

# Decode IV if present
iv_bytes = None
if iv_base64:
    try:
        iv_bytes = base64.b64decode(iv_base64)
    except Exception:
        st.error("Invalid Base64 IV.")

# --- Mode & Format Selection ---
col1, col2 = st.columns(2)

with col1:
    st.markdown("<strong>Encryption Mode</strong>", unsafe_allow_html=True)
    mode = st.radio("", ["ECB", "CBC"], index=1)

with col2:
    st.markdown("<strong>Output Format</strong>", unsafe_allow_html=True)
    output_format = st.radio("", ["Base64", "Hexadecimal"], index=0)

# --- Buttons ---
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    if st.button("Encrypt"):
        try:
            encrypted_data = encrypt_aes(input_text, key_bytes, mode, iv_bytes)
            if output_format == "Base64":
                result = base64.b64encode(encrypted_data).decode('utf-8')
            else:
                result = binascii.hexlify(encrypted_data).decode('utf-8')
            st.session_state.output = result
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")

with col2:
    if st.button("Decrypt"):
        try:
            encrypted_data = base64.b64decode(st.session_state.output) if output_format == "Base64" else binascii.unhexlify(st.session_state.output)
            decrypted_text = decrypt_aes(encrypted_data, key_bytes, mode, iv_bytes)
            st.session_state.output = decrypted_text
        except Exception as e:
            st.error(f"Decryption failed: {str(e)}")

with col3:
    if st.button("Clear All"):
        st.session_state.output = ""
        st.session_state.secret_key = ""
        st.session_state.iv = ""
        input_text = ""

# --- Output ---
st.markdown("<div class='container'><strong>Output</strong></div>", unsafe_allow_html=True)
output = st.text_area("", value=getattr(st.session_state, 'output', ''), height=100, key="output_area")