import os
from flask import Flask, request, render_template
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

def readFile(file_path):
    binary_extensions = ['.jpg', '.png', '.img', '.jpeg', '.gif', '.bmp', '.docx']
    _, file_extension = os.path.splitext(file_path)
    
    if file_extension.lower() in binary_extensions:
        with open(file_path, 'rb') as file:
            content = file.read()
        file_type = 'binary'
    else:
        with open(file_path, 'r') as file:
            content = file.read()
        file_type = 'text'
    
    return content, file_type

def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def get_file_path():
    root = tk.Tk()
    root.attributes('-topmost', True)
    root.lift()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    root.destroy()
    return file_path

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def browse_file():
    file_path = get_file_path()
    if file_path:
        return render_template('index.html', file_path=file_path)
    else:
        return render_template('index.html', error="Wrong File Path.")

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    file_path = request.form.get('file_path')
    lock = request.form.get('password')
    
    if not lock:
        return render_template('index.html', error="Password cannot be empty")
    
    key, salt = derive_key(lock)
    if file_path and key:
        fernet = Fernet(key)
        original_data, file_type = readFile(file_path)
        if file_type == 'binary':
            encrypted_data = fernet.encrypt(original_data)
        else:
            encrypted_data = fernet.encrypt(original_data.encode())

        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted_data)

        return render_template('index.html', encrypted="True", file_path=file_path)
    else:
        return render_template('index.html', error="Something Went Wrong.")

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    file_path = request.form.get('file_path')
    lock = request.form.get('password')
    
    if not lock:
        return render_template('index.html', error="Password cannot be empty")
    try:
        if file_path and lock:
            with open(file_path, 'rb') as encrypted_file:
                salt = encrypted_file.read(16)
                encrypted_data = encrypted_file.read()

            key, _ = derive_key(lock, salt)
            fernet = Fernet(key) 
            decrypted_data = fernet.decrypt(encrypted_data)

            binary_extensions = ['.jpg', '.png', '.img', '.jpeg', '.gif', '.bmp', '.docx']
            _, file_extension = os.path.splitext(file_path)

            if file_extension.lower() in binary_extensions:
                with open(file_path, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_data)
            else:
                with open(file_path, 'w') as decrypted_file:
                    decrypted_file.write(decrypted_data.decode('utf-8'))

            return render_template('index.html', decrypted="True", file_path=file_path)
    except Exception:
        return render_template('index.html', error="Something Went Wrong.", file_path=file_path)

if __name__ == '__main__':
    app.run(debug=True)
