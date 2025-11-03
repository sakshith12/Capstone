from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for, flash, Response
import os
import random
import string
import time
import threading
from datetime import datetime, timedelta
import atexit
import hashlib
import base64
import json
import io
import re
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from functools import wraps
import bcrypt
import secrets

# Configure logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configuration
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024

# In-memory storage (replace with database in production)
users_db = {}
user_keys = {}
file_data = {}
file_shares = {}  # file_code -> {'shared_with': [usernames], 'owner': username}
shared_files = {}  # username -> [shared_file_info]

# Allowed file extensions with magic numbers
FILE_SIGNATURES = {
    'pdf': [b'%PDF'],
    'png': [b'\x89PNG\r\n\x1a\n'],
    'jpg': [b'\xff\xd8\xff'],
    'jpeg': [b'\xff\xd8\xff'],
    'gif': [b'GIF87a', b'GIF89a'],
    'zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
    'txt': [],  # No specific signature for text files
    'doc': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],  # MS Office
    'docx': [b'PK\x03\x04'],  # DOCX is a zip file
    'xls': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'xlsx': [b'PK\x03\x04'],
    'ppt': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'pptx': [b'PK\x03\x04'],
    'mp4': [b'\x00\x00\x00\x18ftypmp42', b'\x00\x00\x00\x20ftypmp42'],
    'mp3': [b'ID3', b'\xff\xfb']
}

ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx',
    'ppt', 'pptx', 'mp4', 'mp3', 'zip', 'rar'
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_signature(file_bytes, filename):
    """Validate file magic number matches extension"""
    extension = filename.rsplit('.', 1)[-1].lower()
    
    if extension not in FILE_SIGNATURES:
        return True  # No signature defined for this extension
    
    signatures = FILE_SIGNATURES[extension]
    if not signatures:  # No specific signature required
        return True
    
    # Check if file matches any of the expected signatures
    for signature in signatures:
        if file_bytes.startswith(signature):
            return True
    
    return False

def validate_username(username):
    """Validate username: 8-20 characters, alphanumeric and underscores only"""
    if len(username) < 8 or len(username) > 20:
        return False, "Username must be between 8 and 20 characters"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, "Valid username"

def validate_password(password):
    """Validate password: 8-20 characters, at least one letter and one number"""
    if len(password) < 8 or len(password) > 20:
        return False, "Password must be between 8 and 20 characters"
    
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    return True, "Valid password"

def generate_unique_access_code():
    """Generate unique access code that doesn't exist in file_data"""
    while True:
        access_code = generate_pin()
        # Check if access code already exists in file_data
        if access_code not in file_data:
            # Check if encrypted file already exists
            encrypted_file_path = os.path.join(UPLOAD_FOLDER, f"{access_code}.enc")
            if not os.path.exists(encrypted_file_path):
                return access_code

class DiffieHellmanManager:
    # Generate DH parameters once
    DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    
    @staticmethod
    def generate_key_pair():
        """Generate DH key pair for a user"""
        private_key = DiffieHellmanManager.DH_PARAMETERS.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def perform_key_exchange(private_key, peer_public_key):
        """Perform DH key exchange and derive shared secret"""
        shared_secret = private_key.exchange(peer_public_key)
        
        # Derive a symmetric key from the shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'dh-key-exchange',
        ).derive(shared_secret)
        
        return derived_key
    
    @staticmethod
    def encrypt_with_shared_secret(data, shared_secret):
        """Encrypt data using the shared secret"""
        # Derive Fernet key from shared secret
        fernet_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'fernet-key',
        ).derive(shared_secret)
        
        fernet_key_b64 = base64.urlsafe_b64encode(fernet_key)
        cipher = Fernet(fernet_key_b64)
        encrypted_data = cipher.encrypt(data.encode() if isinstance(data, str) else data)
        return base64.b64encode(encrypted_data).decode()
    
    @staticmethod
    def decrypt_with_shared_secret(encrypted_data_b64, shared_secret):
        """Decrypt data using the shared secret"""
        fernet_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'fernet-key',
        ).derive(shared_secret)
        
        fernet_key_b64 = base64.urlsafe_b64encode(fernet_key)
        cipher = Fernet(fernet_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode()

class UserManager:
    @staticmethod
    def create_user(username, password):
        """Create new user with DH key pair"""
        if username in users_db:
            return False, "Username already exists"
        
        # Validate username
        username_valid, username_msg = validate_username(username)
        if not username_valid:
            return False, username_msg
        
        # Validate password
        password_valid, password_msg = validate_password(password)
        if not password_valid:
            return False, password_msg
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        # Generate DH key pair
        private_key, public_key = DiffieHellmanManager.generate_key_pair()
        
        # Serialize keys
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Store user data
        users_db[username] = {
            'password_hash': password_hash,
            'created_at': datetime.now(),
            'public_key': public_key_pem.decode(),
            'dh_parameters': DiffieHellmanManager.DH_PARAMETERS.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            ).decode()
        }
        
        user_keys[username] = {
            'private_key': private_key_pem,
            'public_key': public_key_pem
        }
        
        # Initialize shared files list
        shared_files[username] = []
        
        return True, "User created successfully"
    
    @staticmethod
    def authenticate_user(username, password):
        """Authenticate user and load their keys"""
        if username not in users_db:
            return False, "Invalid credentials"
        
        user_data = users_db[username]
        if not bcrypt.checkpw(password.encode(), user_data['password_hash']):
            return False, "Invalid credentials"
        
        # Store password in session for key operations (temporary)
        session['user_password'] = password
        
        # Load user's private key
        try:
            private_key = serialization.load_pem_private_key(
                user_keys[username]['private_key'],
                password=password.encode()
            )
            
            session['username'] = username
            session['public_key'] = user_keys[username]['public_key'].decode()
            session['authenticated'] = True
            session['private_key_loaded'] = True
            
            return True, "Authentication successful"
        except Exception as e:
            return False, "Failed to load user keys"
    
    @staticmethod
    def get_user_public_key(username):
        """Get user's public key"""
        if username in users_db:
            return users_db[username]['public_key']
        return None

class KeySharingManager:
    @staticmethod
    def share_file_with_users(file_code, decryption_key, sender_username, recipient_usernames):
        """Share file with multiple users using Diffie-Hellman"""
        shared_data = {}
        
        # Initialize file shares if not exists
        if file_code not in file_shares:
            file_shares[file_code] = {
                'shared_with': [],
                'owner': sender_username
            }
        
        for recipient in recipient_usernames:
            if recipient not in users_db:
                continue
            
            try:
                # Load sender's private key using stored password
                sender_private_key = serialization.load_pem_private_key(
                    user_keys[sender_username]['private_key'],
                    password=session.get('user_password', '').encode()
                )
                
                # Load recipient's public key
                recipient_public_key_pem = users_db[recipient]['public_key']
                recipient_public_key = serialization.load_pem_public_key(
                    recipient_public_key_pem.encode()
                )
                
                # Perform DH key exchange
                shared_secret = DiffieHellmanManager.perform_key_exchange(
                    sender_private_key, recipient_public_key
                )
                
                # Encrypt the decryption key with shared secret
                encrypted_key = DiffieHellmanManager.encrypt_with_shared_secret(
                    decryption_key, shared_secret
                )
                
                shared_data[recipient] = encrypted_key
                
                # Add to recipient's shared files
                shared_file_info = {
                    'file_code': file_code,
                    'sender': sender_username,
                    'encrypted_key': encrypted_key,
                    'timestamp': datetime.now(),
                    'access_code': file_code,
                    'decryption_key': decryption_key
                }
                
                # Check if file already shared to avoid duplicates
                if not any(f['file_code'] == file_code for f in shared_files[recipient]):
                    shared_files[recipient].append(shared_file_info)
                
                # Add to file shares for access control
                if recipient not in file_shares[file_code]['shared_with']:
                    file_shares[file_code]['shared_with'].append(recipient)
                
            except Exception as e:
                logger.error(f"Error sharing with {recipient}: {str(e)}")
                continue
        
        return shared_data

def generate_pin():
    """Generate 6-digit alphanumeric code"""
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(6))

def derive_key(pin):
    """Derive encryption key from PIN"""
    salt = b"secure_salt_value"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

def calculate_file_hash(file_bytes):
    """Calculate SHA256 hash of file"""
    return hashlib.sha256(file_bytes).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def can_access_file(file_code, username):
    """Check if user can access the file"""
    if file_code not in file_data:
        return False
    
    file_info = file_data[file_code]
    
    # File owner can always access
    if file_info.get('owner') == username:
        return True
    
    # Check if user is in shared_with list
    if (file_code in file_shares and 
        username in file_shares[file_code]['shared_with']):
        return True
    
    return False

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        success, message = UserManager.authenticate_user(username, password)
        if success:
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(message, 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        success, message = UserManager.create_user(username, password)
        if success:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
    
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    user_shared_files = shared_files.get(username, [])
    
    # Get files sent by user
    user_sent_files = []
    for file_code, file_info in file_data.items():
        if file_info.get('owner') == username:
            user_sent_files.append(file_info)
    
    return render_template('dashboard.html', 
                         username=username,
                         shared_files=user_shared_files,
                         sent_files=user_sent_files)

@app.route('/delete_file/<file_code>', methods=['POST'])
@login_required
def delete_file(file_code):
    username = session['username']
    
    if file_code not in file_data:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    
    file_info = file_data[file_code]
    
    # Check if user is owner or recipient
    if file_info.get('owner') == username:
        # Owner deleting - remove from all recipients
        try:
            # Remove encrypted file from disk
            encrypted_file_path = file_info["path"]
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)
            
            # Remove from all recipients' shared files
            if file_code in file_shares:
                for recipient in file_shares[file_code]['shared_with']:
                    if recipient in shared_files:
                        shared_files[recipient] = [f for f in shared_files[recipient] if f['file_code'] != file_code]
            
            # Remove from file_data and file_shares
            del file_data[file_code]
            if file_code in file_shares:
                del file_shares[file_code]
            
            flash('File deleted successfully (removed from all recipients)', 'success')
            
        except Exception as e:
            logger.error(f"Delete error: {str(e)}")
            flash('Error deleting file', 'error')
    
    else:
        # Recipient deleting - remove only from their dashboard
        if username in shared_files:
            shared_files[username] = [f for f in shared_files[username] if f['file_code'] != file_code]
            flash('File removed from your dashboard', 'success')
        else:
            flash('File not found in your dashboard', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/send', methods=['GET', 'POST'])
@login_required
def send_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('send_file'))
        
        file = request.files['file']
        recipients = request.form.get('recipients', '').strip()
        encryption_key = request.form.get('encryption_key', '').strip().upper()
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('send_file'))
        
        # Validate file type
        if not allowed_file(file.filename):
            flash('File type not allowed', 'error')
            return redirect(url_for('send_file'))
        
        # Generate encryption key if not provided
        if not encryption_key:
            encryption_key = generate_pin()
        elif len(encryption_key) != 6 or not all(c in (string.ascii_uppercase + string.digits) for c in encryption_key):
            flash('Encryption key must be 6-character alphanumeric', 'error')
            return redirect(url_for('send_file'))
        
        try:
            # Read and process file
            file_bytes = file.read()
            
            # Validate file signature
            if not validate_file_signature(file_bytes, file.filename):
                extension = file.filename.rsplit('.', 1)[-1].lower()
                flash(f'File signature does not match the extension (.{extension}). File may be corrupted or mislabeled.', 'error')
                return redirect(url_for('send_file'))
            
            file_hash = calculate_file_hash(file_bytes)
            
            # Encrypt file
            derived_key = derive_key(encryption_key)
            cipher = Fernet(derived_key)
            encrypted_data = cipher.encrypt(file_bytes)
            
            # Generate unique access code
            access_code = generate_unique_access_code()
            
            # Store ONLY encrypted file data
            filename = file.filename
            encrypted_file_path = os.path.join(UPLOAD_FOLDER, f"{access_code}.enc")
            
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_data)
            
            # Store file metadata (NO plain file stored)
            file_data[access_code] = {
                "path": encrypted_file_path,
                "filename": filename,
                "owner": session['username'],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "size_mb": round(len(file_bytes) / (1024 * 1024), 2),
                "hash": file_hash,
                "encryption_key": encryption_key,
                "access_code": access_code
            }
            
            # Initialize file shares
            file_shares[access_code] = {
                'shared_with': [],
                'owner': session['username']
            }
            
            # Share with recipients
            if recipients:
                recipient_list = [r.strip() for r in recipients.split(',') if r.strip()]
                valid_recipients = []
                invalid_recipients = []
                
                for recipient in recipient_list:
                    if recipient in users_db and recipient != session['username']:
                        valid_recipients.append(recipient)
                    else:
                        invalid_recipients.append(recipient)
                
                if valid_recipients:
                    KeySharingManager.share_file_with_users(
                        access_code, encryption_key, session['username'], valid_recipients
                    )
                    flash(f'File shared with: {", ".join(valid_recipients)}', 'success')
                
                if invalid_recipients:
                    flash(f'Invalid or non-existent users: {", ".join(invalid_recipients)}', 'error')
            
            flash(f'File uploaded successfully! Access Code: {access_code}, Encryption Key: {encryption_key}', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            flash(f'Upload failed: {str(e)}', 'error')
    
    return render_template('send.html')

@app.route('/download', methods=['GET', 'POST'])
@login_required
def download_file():
    if request.method == 'POST':
        access_code = request.form.get('access_code', '').strip().upper()
        decryption_key = request.form.get('decryption_key', '').strip().upper()
        username = session['username']
        
        if not access_code or not decryption_key:
            flash('Both access code and decryption key are required', 'error')
            return redirect(url_for('download_file'))
        
        if access_code not in file_data:
            flash('Invalid access code', 'error')
            return redirect(url_for('download_file'))
        
        # Check if user has access to this file
        if not can_access_file(access_code, username):
            flash('Access denied: You are not authorized to download this file', 'error')
            return redirect(url_for('download_file'))
        
        try:
            file_info = file_data[access_code]
            encrypted_file_path = file_info["path"]
            
            if not os.path.exists(encrypted_file_path):
                flash('File not found or expired', 'error')
                return redirect(url_for('download_file'))
            
            # Read encrypted file
            with open(encrypted_file_path, "rb") as f:
                encrypted_data = f.read()
            
            # Decrypt file in memory
            derived_key = derive_key(decryption_key)
            cipher = Fernet(derived_key)
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # Verify hash
            decrypted_hash = calculate_file_hash(decrypted_data)
            if decrypted_hash != file_info['hash']:
                flash('File integrity check failed - file may be corrupted', 'error')
                return redirect(url_for('download_file'))
            
            # Universal download method that works with all Flask versions
            response = Response(
                decrypted_data,
                mimetype='application/octet-stream',
                headers={
                    'Content-Disposition': f'attachment; filename="{file_info["filename"]}"',
                    'Content-Length': str(len(decrypted_data))
                }
            )
            return response
            
        except Exception as e:
            logger.error(f"Download error: {str(e)}")
            if "InvalidToken" in str(e) or "Signature" in str(e):
                flash('Download failed: Invalid decryption key', 'error')
            else:
                flash(f'Download failed: {str(e)}', 'error')
    
    # Get user's shared files for display
    username = session['username']
    user_shared_files = shared_files.get(username, [])
    
    return render_template('download.html', shared_files=user_shared_files)

@app.route('/logout')
def logout():
    # Clear password from session for security
    if 'user_password' in session:
        del session['user_password']
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

def cleanup_old_files():
    """Clean up encrypted files older than 24 hours"""
    now = datetime.now()
    files_to_remove = []
    
    for file_code, file_info in list(file_data.items()):
        try:
            file_time = datetime.strptime(file_info['timestamp'], "%Y-%m-%d %H:%M:%S")
            if now - file_time > timedelta(hours=24):
                # Remove encrypted file only
                if os.path.exists(file_info['path']):
                    os.remove(file_info['path'])
                files_to_remove.append(file_code)
                
                # Remove from file_shares
                if file_code in file_shares:
                    del file_shares[file_code]
        except:
            continue
    
    # Remove from file_data
    for file_code in files_to_remove:
        if file_code in file_data:
            del file_data[file_code]
    
    # Clean up shared files references
    for user_files in shared_files.values():
        user_files[:] = [f for f in user_files if f['file_code'] not in files_to_remove]

# Initialize cleanup thread
def cleanup_worker():
    while True:
        cleanup_old_files()
        time.sleep(3600)  # Run every hour

cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    print("Starting Secure File Transfer System...")
    print("Access the application at: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)