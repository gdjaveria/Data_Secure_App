import streamlit as st
import sqlite3
import hashlib
from cryptography.fernet import Fernet
import os

# database connection
KEY_FILE = 'simple_secret.key'
DB_FILE = 'users_data.db'   # Database file name

# Encrypted setup
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    return open(KEY_FILE,'rb').read()

Cipher = Fernet(load_key())

# Database setup
def init_db():
    conn = sqlite3.connect(DB_FILE)
    C = conn.cursor()
    C.execute("""CREATE TABLE IF NOT EXISTS users (label TEXT PRIMARY KEY, encrypted_text TEXT NOT NULL,
              passkey TEXT NOT NULL)""")
    conn.commit()
    conn.close()

init_db()

# Security functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
    
def encrypted_text(text):
    return Cipher.encrypt(text.encode()).decode()
    
def decrypted_text(encrypted_text):
    return Cipher.decrypt(encrypted_text.encode()).decode()
    
# Streamlit App
st.title('🔐 Secure Data Encryption App')
menu = ['Store Data', 'Retrieve Data']
choice = st.sidebar.selectbox('Select an option', menu)

if choice == 'Store Data':
    st.header('📦 Store your Data Securely')
    label = st.text_input('Label for your data (Unique identifer):')
    passkey = st.text_input('Enter your passkey:(min 8 characters)', type='password')
    secret = st.text_area('Enter the secret data:')

    if st.button('Encrypt and save'):
        if not all([label, secret, passkey]):
            st.warning('Please fill all fields')
        elif len(passkey) < 8:
            st.error('❌ Password must be at least 8 characters')
        else:
            try:
                encrypted = encrypted_text(secret)
                hashed_key = hash_passkey(passkey)
# Store the encrypted data in the database
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('INSERT INTO users (label, encrypted_text, passkey) VALUES (?,?,?)',
                              (label, encrypted, hashed_key))
                conn.commit()
                st.success('✅ Data encrypted and saved successfully!')
            except sqlite3.IntegrityError:
                st.error('❌ Label already exists. Please choose a different label.')
            except Exception as e:
                st.error(f'❌ An error occurred: {e}')
            finally:
                conn.close()

elif choice == 'Retrieve Data':
    st.header('🔍 Retrieve your Data')
    label = st.text_input('Enter the label of the data:')
    passkey =st.text_input('Enter your passkey:', type='password')

    if st.button('Decrypt and Retrieve'):
        if not label or not passkey:
            st.warning('Please fill all fields')
        else:
            try:
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                c.execute('SELECT encrypted_text, passkey FROM users WHERE label = ?', (label,))
                result = c.fetchone()
                conn.close()

                if result:
                    encrypted_text, stored_hashed_key = result
                    if hash_passkey(passkey) == stored_hashed_key:
                        decrypted_text = decrypted_text(encrypted_text)
                        st.success('✅ Data retrieved successfully!')
                        st.code(decrypted_text)
                    else:
                        st.error('❌ Incorrect passkey. please try again.')
                else:
                    st.warning('❌Label not found. please check the label and try again.')
            except Exception as e:
                st.error(f'❌ An error occurred: {e}')
            

           
        

                   

                   

        


    
   
        
        