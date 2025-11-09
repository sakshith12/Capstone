from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import os
import string
import time
import threading
from datetime import datetime, timedelta
import hashlib
import base64
import re
import uuid
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
from supabase import create_client, Client
from dotenv import load_dotenv
import jwt

load_dotenv()

import logging
logging.basicConfig()
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
# Allow multiple frontend URLs for development (port 3000, 8000, and production)
ALLOWED_ORIGINS = [FRONTEND_URL, 'http://localhost:8000', 'http://localhost:3000', 'http://127.0.0.1:8000', 'http://127.0.0.1:3000']
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS, "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"], "supports_credentials": True}})

app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
JWT_EXPIRATION_HOURS = 24

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
SUPABASE_BUCKET = os.environ.get('SUPABASE_BUCKET', 'encrypted-files')
USE_LOCAL_STORAGE = os.environ.get('USE_LOCAL_STORAGE', 'false').lower() == 'true'

supabase: Client = None
if not USE_LOCAL_STORAGE and SUPABASE_URL and SUPABASE_KEY and SUPABASE_URL != 'https://your-project-id.supabase.co':
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Failed to initialize Supabase: {e}")
        USE_LOCAL_STORAGE = True
elif not USE_LOCAL_STORAGE:
    print("Supabase configuration incomplete, falling back to local storage")
    USE_LOCAL_STORAGE = True

local_users = {}
local_files = {}
local_storage = {}
file_shares = {}
shared_files = {}

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
user_id_counter = [1]

FILE_SIGNATURES = {
    'pdf': [b'%PDF'],
    'png': [b'\x89PNG\r\n\x1a\n'],
    'jpg': [b'\xff\xd8\xff'],
    'jpeg': [b'\xff\xd8\xff'],
    'gif': [b'GIF87a', b'GIF89a'],
    'zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
    'rar': [b'Rar!\x1a\x07', b'Rar!\x1a\x07\x01\x00'],
    'txt': [],
    'doc': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'docx': [b'PK\x03\x04'],
    'xls': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'xlsx': [b'PK\x03\x04'],
    'ppt': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'pptx': [b'PK\x03\x04'],
    'mp4': [b'\x00\x00\x00\x18ftypmp42', b'\x00\x00\x00\x20ftypmp42', b'ftypisom', b'ftypmp42'],
    'mp3': [b'ID3', b'\xff\xfb', b'\xff\xf3', b'\xff\xf2'],
    'avi': [b'RIFF'],
    'mov': [b'\x00\x00\x00\x14ftyp', b'moov'],
    'mkv': [b'\x1a\x45\xdf\xa3'],
    'wav': [b'RIFF'],
    'flac': [b'fLaC'],
    'bmp': [b'BM'],
    'webp': [b'RIFF'],
    'svg': [b'<?xml', b'<svg'],
    'ico': [b'\x00\x00\x01\x00'],
    'exe': [b'MZ'],
    'dmg': [b'\x78\x01\x73\x0d\x62\x62\x60'],
    'apk': [b'PK\x03\x04'],
    '7z': [b'7z\xbc\xaf\x27\x1c']
}

ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx',
    'ppt', 'pptx', 'mp4', 'mp3', 'zip', 'rar', 'avi', 'mov', 'mkv', 'wav',
    'flac', 'bmp', 'webp', 'svg', 'ico', '7z'
}

 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_signature(file_bytes, filename):
    """Validate file magic number matches the extension"""
    extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    
    if extension not in FILE_SIGNATURES:
        return True
    
    signatures = FILE_SIGNATURES[extension]
    
    if not signatures:
        return True
    
    for signature in signatures:
        if file_bytes.startswith(signature):
            return True
    
    actual_signature = file_bytes[:20] if len(file_bytes) >= 20 else file_bytes
    return False

def validate_username(username):
    if len(username) < 8 or len(username) > 20:
        return False, "Username must be between 8 and 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Valid username"

def validate_password(password):
    if len(password) < 8 or len(password) > 20:
        return False, "Password must be between 8 and 20 characters"
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Valid password"

def generate_unique_access_code():
    while True:
        access_code = generate_pin()
        if USE_LOCAL_STORAGE:
            # Check both in-memory dict and physical file existence
            file_path = os.path.join(UPLOAD_FOLDER, f"{access_code}.enc")
            if access_code not in local_files and not os.path.exists(file_path):
                return access_code
        else:
            result = supabase.table('files').select('access_code').eq('access_code', access_code).execute()
            if not result.data:
                return access_code

def generate_pin():
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(6))

def derive_key(pin):
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
    return hashlib.sha256(file_bytes).hexdigest()

def generate_jwt_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        pass
        return None
    except jwt.InvalidTokenError:
        pass
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                pass
                return jsonify({'success': False, 'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({'success': False, 'error': 'Token is invalid or expired'}), 401
        
        return f(payload, *args, **kwargs)
    return decorated

 
class DiffieHellmanManager:
    _DH_PARAMETERS = None
    
    @classmethod
    def get_dh_parameters(cls):
        if cls._DH_PARAMETERS is None:
            
            cls._DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            
        return cls._DH_PARAMETERS
    
    @staticmethod
    def generate_key_pair():
        private_key = DiffieHellmanManager.get_dh_parameters().generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def perform_key_exchange(private_key, peer_public_key):
        shared_secret = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'dh-key-exchange',
        ).derive(shared_secret)
        return derived_key
    
    @staticmethod
    def encrypt_with_shared_secret(data, shared_secret):
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


class DHEncryptionKeyManager:
    """Manages encryption and decryption of file encryption keys using user's permanent DH keys"""
    
    @staticmethod
    def encrypt_key_with_public_key(encryption_key, sender_private_key_encrypted, sender_password_hash, recipient_public_key_pem):
        """
        Encrypt an encryption key using DH key exchange between sender and recipient
        Uses sender's private key and recipient's public key
        """
        try:
            # Decrypt sender's private key
            sender_private_key = serialization.load_pem_private_key(
                base64.b64decode(sender_private_key_encrypted),
                password=sender_password_hash.encode() if isinstance(sender_password_hash, str) else sender_password_hash,
                backend=default_backend()
            )
            
            # Load recipient's public key
            recipient_public_key = serialization.load_pem_public_key(
                recipient_public_key_pem.encode() if isinstance(recipient_public_key_pem, str) else recipient_public_key_pem,
                backend=default_backend()
            )
            
            # Perform key exchange to get shared secret
            shared_secret = sender_private_key.exchange(recipient_public_key)
            
            # Derive encryption key from shared secret
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'dh-file-key-salt',
                info=b'dh-file-key-encryption',
                backend=default_backend()
            ).derive(shared_secret)
            
            # Encrypt the encryption key with derived key
            fernet_key_b64 = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key_b64)
            encrypted_key = cipher.encrypt(
                encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
            )
            
            # Return encrypted key (no ephemeral key needed!)
            return {
                'encrypted_key': base64.b64encode(encrypted_key).decode()
            }
        except Exception as e:
            logger.error(f"Error in encrypt_key_with_public_key: {str(e)}")
            raise Exception(f"Error encrypting key with public key: {str(e)}")
    
    @staticmethod
    def decrypt_key_with_private_key(encrypted_key_data, user_private_key_encrypted, user_password_hash, sender_public_key_pem):
        """
        Decrypt an encryption key using DH key exchange
        Uses user's private key and sender's public key to derive same shared secret
        """
        try:
            # Decrypt user's private key using their password hash
            user_private_key = serialization.load_pem_private_key(
                base64.b64decode(user_private_key_encrypted),
                password=user_password_hash.encode() if isinstance(user_password_hash, str) else user_password_hash,
                backend=default_backend()
            )
            
            # Load the sender's public key
            sender_public_key = serialization.load_pem_public_key(
                sender_public_key_pem.encode() if isinstance(sender_public_key_pem, str) else sender_public_key_pem,
                backend=default_backend()
            )
            
            # Perform key exchange to get shared secret (same as encryption)
            shared_secret = user_private_key.exchange(sender_public_key)
            
            # Derive decryption key from shared secret
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'dh-file-key-salt',
                info=b'dh-file-key-encryption',
                backend=default_backend()
            ).derive(shared_secret)
            
            # Decrypt the encryption key
            fernet_key_b64 = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key_b64)
            encrypted_key_bytes = base64.b64decode(encrypted_key_data['encrypted_key'])
            decrypted_key = cipher.decrypt(encrypted_key_bytes)
            
            return decrypted_key.decode()
        except Exception as e:
            logger.error(f"Error in decrypt_key_with_private_key: {str(e)}")
            raise Exception(f"Error decrypting key with private key: {str(e)}")


class EncryptionKeyManager:
    """Legacy: Manages encryption and decryption of file encryption keys using user's password-based encryption"""
    
    @staticmethod
    def encrypt_key_for_user(encryption_key, user_password_hash):
        """Encrypt an encryption key using user's password hash as key material"""
        try:
            # Derive encryption key from user's password hash
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'file-key-salt',
                info=b'file-key-encryption',
                backend=default_backend()
            ).derive(user_password_hash.encode() if isinstance(user_password_hash, str) else user_password_hash)
            
            # Encrypt the encryption key
            fernet_key_b64 = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key_b64)
            encrypted_key = cipher.encrypt(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
            
            # Return the encrypted key
            return {
                'encrypted_key': base64.b64encode(encrypted_key).decode()
            }
        except Exception as e:
            logger.error(f"Error in encrypt_key_for_user: {str(e)}")
            raise Exception(f"Error encrypting key: {str(e)}")
    
    @staticmethod
    def decrypt_key_for_user(encrypted_key_data, user_password_hash, password):
        """Decrypt an encryption key using user's password hash"""
        try:
            # Derive decryption key from user's password hash
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'file-key-salt',
                info=b'file-key-encryption',
                backend=default_backend()
            ).derive(user_password_hash.encode() if isinstance(user_password_hash, str) else user_password_hash)
            
            # Decrypt the encryption key
            fernet_key_b64 = base64.urlsafe_b64encode(derived_key)
            cipher = Fernet(fernet_key_b64)
            encrypted_key_bytes = base64.b64decode(encrypted_key_data['encrypted_key'])
            decrypted_key = cipher.decrypt(encrypted_key_bytes)
            
            return decrypted_key.decode()
        except Exception as e:
            logger.error(f"Error in decrypt_key_for_user: {str(e)}")
            raise Exception(f"Error decrypting key: {str(e)}")

 
class UserManager:
    @staticmethod
    def create_user(username, password):
        try:
            if USE_LOCAL_STORAGE:
                if username in local_users:
                    return False, "Username already exists"
            else:
                result = supabase.table('users').select('username').eq('username', username).execute()
                if result.data:
                    return False, "Username already exists"
            
            username_valid, username_msg = validate_username(username)
            if not username_valid:
                return False, username_msg
            
            password_valid, password_msg = validate_password(password)
            if not password_valid:
                return False, password_msg
            
            # Use lower rounds for free tier performance (10 instead of default 12)
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()
            private_key, public_key = DiffieHellmanManager.generate_key_pair()
            
            # Encrypt private key with password hash instead of plain password
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password_hash.encode())
            )
            
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            dh_parameters_pem = DiffieHellmanManager.get_dh_parameters().parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            
            user_data = {
                'username': username,
                'password_hash': password_hash,
                'public_key': public_key_pem.decode(),
                'dh_parameters': dh_parameters_pem.decode(),
                'private_key_encrypted': base64.b64encode(private_key_pem).decode()
            }
            
            if USE_LOCAL_STORAGE:
                user_id = user_id_counter[0]
                user_id_counter[0] += 1
                user_data['id'] = user_id
                user_data['created_at'] = datetime.now().isoformat()
                local_users[username] = user_data
                result_data = [user_data]
            else:
                result = supabase.table('users').insert(user_data).execute()
                result_data = result.data
            
            if result_data:
                return True, "User created successfully"
            else:
                return False, "Failed to create user"
                
        except Exception as e:
            
            return False, f"Error creating user: {str(e)}"
    
    @staticmethod
    def authenticate_user(username, password):
        try:
            if USE_LOCAL_STORAGE:
                if username not in local_users:
                    return False, "Invalid credentials", None
                user_data = local_users[username]
            else:
                result = supabase.table('users').select('*').eq('username', username).execute()
                
                if not result.data:
                    return False, "Invalid credentials", None
                
                user_data = result.data[0]
            
            if not bcrypt.checkpw(password.encode(), user_data['password_hash'].encode()):
                return False, "Invalid credentials", None
            
            return True, "Authentication successful", user_data
                
        except Exception as e:
            
            return False, "Authentication failed", None
    
    @staticmethod
    def get_user_id(username):
        try:
            result = supabase.table('users').select('id').eq('username', username).execute()
            if result.data:
                return result.data[0]['id']
            return None
        except Exception as e:
            
            return None

 

def can_access_file(access_code, username):
    """Check if user can access the file - only owner and intended recipients allowed"""
    if USE_LOCAL_STORAGE:
        if access_code not in local_files:
            
            return False
        
        file_info = local_files[access_code]
        
        # File owner can always access
        if file_info.get('owner_username') == username:
            
            return True
        
        # Check if user is in shared_with list
        if (access_code in file_shares and 
            username in file_shares[access_code]['shared_with']):
            
            return True
        
        
        return False
    else:
        # Supabase logic - check database for sharing relationships
        try:
            result = supabase.table('files').select('*').eq('access_code', access_code).execute()
            if not result.data:
                return False
            
            file_info = result.data[0]
            
            # Check if user is the owner
            if file_info.get('owner_id') == UserManager.get_user_id(username):
                return True
            
            # Check if user is in shared_with list (would need a shares table in Supabase)
            # For now, allow all authenticated users
            
            return True
        except Exception as e:
            
            return False

 

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'success': True,
        'message': 'Secure File Transfer API',
        'version': '1.0',
        'endpoints': {
            'health': '/api/health',
            'signup': '/api/auth/signup',
            'login': '/api/auth/login',
            'upload': '/api/files/upload',
            'download': '/api/files/download/<access_code>',
            'my_files': '/api/files/my-files'
        }
    }), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'success': True, 'message': 'API is running'}), 200

@app.route('/api/debug/users', methods=['GET'])
def debug_users():
    if USE_LOCAL_STORAGE:
        return jsonify({
            'success': True,
            'storage_mode': 'local',
            'users': list(local_users.keys()),
            'user_count': len(local_users)
        }), 200
    else:
        return jsonify({
            'success': True,
            'storage_mode': 'supabase',
            'message': 'Using Supabase storage'
        }), 200

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password are required'}), 400
    
    success, message = UserManager.create_user(username, password)
    
    
    
    if success:
        return jsonify({'success': True, 'message': message}), 201
    else:
        return jsonify({'success': False, 'error': message}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password are required'}), 400
    
    success, message, user_data = UserManager.authenticate_user(username, password)
    logger.info(f"Login result for {username}: success={success}, message={message}")
    
    if success:
        token = generate_jwt_token(user_data['id'], user_data['username'])
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user_data['id'],
                'username': user_data['username']
            }
        }), 200
    else:
        return jsonify({'success': False, 'error': message}), 401

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(payload):
    return jsonify({
        'success': True,
        'user': {
            'id': payload['user_id'],
            'username': payload['username']
        }
    }), 200

@app.route('/api/users/list', methods=['GET'])
@token_required
def list_all_users(payload):
    """Debug endpoint to list all registered users"""
    if USE_LOCAL_STORAGE:
        usernames = list(local_users.keys())
        user_count = len(usernames)
        return jsonify({
            'success': True,
            'users': usernames,
            'count': user_count,
            'current_user': payload['username']
        }), 200
    else:
        try:
            result = supabase.table('users').select('username').execute()
            usernames = [u['username'] for u in result.data]
            return jsonify({
                'success': True,
                'users': usernames,
                'count': len(usernames),
                'current_user': payload['username']
            }), 200
        except Exception as e:
            pass
            return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/files/upload', methods=['POST'])
@token_required
def upload_file(payload):
    logger.info(f"=== FILE UPLOAD REQUEST START ===")
    logger.info(f"User: {payload['username']}")
    logger.info(f"Form data keys: {list(request.form.keys())}")
    logger.info(f"Form data: {dict(request.form)}")
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    recipients = request.form.get('recipients', '').strip()
    encryption_key = request.form.get('encryption_key', '').strip().upper()
    
    logger.info(f"Recipients value: '{recipients}' (length: {len(recipients)})")
    logger.info(f"send_to_all in form: {('send_to_all' in request.form)}")
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'File type not allowed'}), 400
    
    if not encryption_key:
        encryption_key = generate_pin()
    elif len(encryption_key) != 6 or not all(c in (string.ascii_uppercase + string.digits) for c in encryption_key):
        return jsonify({'success': False, 'error': 'Encryption key must be 6-character alphanumeric'}), 400
    
    try:
        file_bytes = file.read()
        
        if not validate_file_signature(file_bytes, file.filename):
            extension = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else 'unknown'
            return jsonify({
                'success': False, 
                'error': f'File validation failed: The file content does not match the .{extension} extension. The file may be corrupted or have an incorrect extension.'
            }), 400
        
        file_hash = calculate_file_hash(file_bytes)
        derived_key = derive_key(encryption_key)
        cipher = Fernet(derived_key)
        encrypted_data = cipher.encrypt(file_bytes)
        
        access_code = generate_unique_access_code()
        
        # Get expiry hours from request
        expiry_hours = int(request.form.get('expiry_hours', 24))
        expiry_time = datetime.utcnow() + timedelta(hours=expiry_hours)
        
        # Get owner's keys to encrypt the encryption key using their own DH keys
        if USE_LOCAL_STORAGE:
            owner_user = local_users.get(payload['username'])
            owner_public_key = owner_user['public_key']
            owner_private_key_encrypted = owner_user['private_key_encrypted']
            owner_password_hash = owner_user['password_hash']
        else:
            owner_result = supabase.table('users').select('public_key, private_key_encrypted, password_hash').eq('id', payload['user_id']).execute()
            owner_public_key = owner_result.data[0]['public_key']
            owner_private_key_encrypted = owner_result.data[0]['private_key_encrypted']
            owner_password_hash = owner_result.data[0]['password_hash']
        
        # Encrypt the encryption key with owner's own keys (sender=owner, recipient=owner)
        encrypted_key_data = DHEncryptionKeyManager.encrypt_key_with_public_key(
            encryption_key, 
            owner_private_key_encrypted,
            owner_password_hash,
            owner_public_key
        )
        
        if USE_LOCAL_STORAGE:
            # Local storage mode
            file_path = os.path.join(UPLOAD_FOLDER, f"{access_code}.enc")
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            file_id = str(uuid.uuid4())
            file_data = {
                'id': file_id,
                'access_code': access_code,
                'filename': file.filename,
                'owner_id': payload['user_id'],
                'owner_username': payload['username'],
                'encrypted_file_path': file_path,
                'encrypted_encryption_key': encrypted_key_data['encrypted_key'],
                'file_hash': file_hash,
                'size_mb': round(len(file_bytes) / (1024 * 1024), 2),
                'timestamp': datetime.utcnow().isoformat(),
                'expiry_time': expiry_time.isoformat()
            }
            local_files[access_code] = file_data
            file_id = file_data['id']
        else:
            # Supabase storage mode
            storage_path = f"{payload['user_id']}/{access_code}.enc"
            supabase.storage.from_(SUPABASE_BUCKET).upload(
                storage_path,
                encrypted_data,
                {'content-type': 'application/octet-stream'}
            )
            
            file_data = {
                'access_code': access_code,
                'filename': file.filename,
                'owner_id': payload['user_id'],
                'encrypted_file_path': storage_path,
                'encrypted_encryption_key': encrypted_key_data['encrypted_key'],
                'file_hash': file_hash,
                'size_mb': round(len(file_bytes) / (1024 * 1024), 2),
                'expiry_time': expiry_time.isoformat()
            }
            
            result = supabase.table('files').insert(file_data).execute()
            file_id = result.data[0]['id']
        
        # Initialize file shares
        file_shares[access_code] = {
            'shared_with': [],
            'owner': payload['username']
        }
        
        # Handle file sharing logic here
        shared_with = []
        send_to_all_flag = request.form.get('send_to_all', '').strip().lower() == 'true'
        logger.info(f"Upload: send_to_all_flag={send_to_all_flag}, recipients={recipients}")
        logger.info(f"Current user: {payload['username']}, All users in system: {list(local_users.keys())}")
        
        if send_to_all_flag:
            # Share with all users (exclude owner)
            if USE_LOCAL_STORAGE:
                logger.info(f"SEND_TO_ALL activated. Current users: {list(local_users.keys())}")
                logger.info(f"Current sender: {payload['username']}")
                for other_username in list(local_users.keys()):
                    logger.info(f"Checking user: {other_username}")
                    if other_username != payload['username']:
                        logger.info(f"Adding {other_username} to shared_with list")
                        shared_with.append(other_username)
                        if other_username not in shared_files:
                            shared_files[other_username] = []
                        
                        # Get recipient's public key and encrypt the encryption key for them using sender's keys
                        recipient_user = local_users.get(other_username)
                        recipient_public_key = recipient_user['public_key']
                        
                        # Use sender's (owner's) keys that we already have
                        recipient_encrypted_key = DHEncryptionKeyManager.encrypt_key_with_public_key(
                            encryption_key, 
                            owner_private_key_encrypted,
                            owner_password_hash,
                            recipient_public_key
                        )
                        
                        shared_file_info = {
                            'file_code': access_code,
                            'access_code': access_code,
                            'sender': payload['username'],
                            'encrypted_key': recipient_encrypted_key['encrypted_key'],
                            'timestamp': datetime.utcnow().isoformat(),
                            'filename': file.filename
                        }
                        if not any(f['file_code'] == access_code for f in shared_files[other_username]):
                            shared_files[other_username].append(shared_file_info)
                            logger.info(f"Added file to {other_username}'s shared_files")
                        if other_username not in file_shares[access_code]['shared_with']:
                            file_shares[access_code]['shared_with'].append(other_username)
                            logger.info(f"Added {other_username} to file_shares")
                    else:
                        logger.info(f"Skipping {other_username} (is the sender)")
                logger.info(f"SEND_TO_ALL complete. Shared file {access_code} with {len(shared_with)} users: {shared_with}")
                logger.info(f"Final shared_files dict keys: {list(shared_files.keys())}")
            else:
                try:
                    result = supabase.table('users').select('id, username, public_key').execute()
                    for u in result.data:
                        uname = u.get('username')
                        uid = u.get('id')
                        upublic_key = u.get('public_key')
                        if uname and uname != payload['username'] and uid and upublic_key:
                            shared_with.append(uname)
                            # Encrypt the encryption key for this recipient using sender's keys
                            recipient_encrypted_key = DHEncryptionKeyManager.encrypt_key_with_public_key(
                                encryption_key,
                                owner_private_key_encrypted,
                                owner_password_hash,
                                upublic_key
                            )
                            # Create file_share entry in Supabase
                            try:
                                supabase.table('file_shares').insert({
                                    'file_id': file_id,
                                    'shared_with_user_id': uid,
                                    'encrypted_key': recipient_encrypted_key['encrypted_key']
                                }).execute()
                            except Exception as share_error:
                                pass
                except Exception as e:
                    pass
        elif recipients:
            recipient_list = [r.strip() for r in recipients.split(',') if r.strip()]
            failed_recipients = []
            
            for recipient in recipient_list:
                # Check if trying to send to self
                if recipient == payload['username']:
                    failed_recipients.append({
                        'username': recipient,
                        'reason': 'Cannot send file to yourself'
                    })
                    logger.warning(f"User {payload['username']} tried to send file to themselves")
                    continue
                
                if USE_LOCAL_STORAGE:
                    # Check if user exists in local storage
                    user_exists = any(u['username'] == recipient for u in local_users.values())
                    
                    if not user_exists:
                        failed_recipients.append({
                            'username': recipient,
                            'reason': 'User not found'
                        })
                        logger.warning(f"User {recipient} not found when sharing file {access_code}")
                        continue
                    
                    # User exists and is not self - add to shared list
                    shared_with.append(recipient)
                    
                    # Initialize recipient's shared files list if needed
                    if recipient not in shared_files:
                        shared_files[recipient] = []
                    
                    # Get recipient's public key and encrypt the encryption key for them using sender's keys
                    recipient_user = next(u for u in local_users.values() if u['username'] == recipient)
                    recipient_public_key = recipient_user['public_key']
                    recipient_encrypted_key = DHEncryptionKeyManager.encrypt_key_with_public_key(
                        encryption_key,
                        owner_private_key_encrypted,
                        owner_password_hash,
                        recipient_public_key
                    )
                    
                    # Add to recipient's shared files
                    shared_file_info = {
                        'file_code': access_code,
                        'access_code': access_code,
                        'sender': payload['username'],
                        'encrypted_key': recipient_encrypted_key['encrypted_key'],
                        'timestamp': datetime.utcnow().isoformat(),
                        'filename': file.filename
                    }
                    
                    # Check if file already shared to avoid duplicates
                    if not any(f['file_code'] == access_code for f in shared_files[recipient]):
                        shared_files[recipient].append(shared_file_info)
                    
                    # Add to file shares
                    if recipient not in file_shares[access_code]['shared_with']:
                        file_shares[access_code]['shared_with'].append(recipient)
                else:
                    recipient_id = UserManager.get_user_id(recipient)
                    
                    if not recipient_id:
                        failed_recipients.append({
                            'username': recipient,
                            'reason': 'User not found'
                        })
                        continue
                    
                    # Get recipient's public key
                    try:
                        recipient_result = supabase.table('users').select('public_key').eq('id', recipient_id).execute()
                        if recipient_result.data and len(recipient_result.data) > 0:
                            recipient_public_key = recipient_result.data[0]['public_key']
                            # Encrypt the encryption key for this recipient using sender's keys
                            recipient_encrypted_key = DHEncryptionKeyManager.encrypt_key_with_public_key(
                                encryption_key,
                                owner_private_key_encrypted,
                                owner_password_hash,
                                recipient_public_key
                            )
                            
                            shared_with.append(recipient)
                            # Create file_share entry in Supabase
                            supabase.table('file_shares').insert({
                                'file_id': file_id,
                                'shared_with_user_id': recipient_id,
                                'encrypted_key': recipient_encrypted_key['encrypted_key']
                            }).execute()
                        else:
                            failed_recipients.append({
                                'username': recipient,
                                'reason': 'User not found'
                            })
                    except Exception as share_error:
                        failed_recipients.append({
                            'username': recipient,
                            'reason': 'Failed to share file'
                        })
        
        # Build response with success and failure details
        response_data = {
            'success': True,
            'access_code': access_code,
            'encryption_key': encryption_key,
            'filename': file.filename,
            'size_mb': file_data['size_mb'],
            'shared_with': shared_with,
            'shared_count': len(shared_with)
        }
        
        # Add failure information if any recipients failed
        if 'failed_recipients' in locals() and failed_recipients:
            response_data['failed_recipients'] = failed_recipients
            response_data['failed_count'] = len(failed_recipients)
            
            # Create a user-friendly message
            if shared_with:
                response_data['message'] = f"File shared with {len(shared_with)} user(s). {len(failed_recipients)} recipient(s) failed."
            else:
                response_data['message'] = f"No valid recipients. All {len(failed_recipients)} recipient(s) failed."
                response_data['warning'] = 'File uploaded but not shared with anyone'
        else:
            if shared_with:
                response_data['message'] = f"File successfully shared with {len(shared_with)} user(s)"
            elif send_to_all_flag:
                response_data['message'] = f"File sent to all {len(shared_with)} user(s)"
            else:
                response_data['message'] = "File uploaded successfully (no recipients specified)"
        
        return jsonify(response_data), 201
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/files/info/<access_code>', methods=['GET'])
@token_required
def get_file_info(payload, access_code):
    try:
        if USE_LOCAL_STORAGE:
            if access_code not in local_files:
                return jsonify({'success': False, 'error': 'Invalid access code'}), 404
            file_data = local_files[access_code]
        else:
            result = supabase.table('files').select('*').eq('access_code', access_code).execute()
            if not result.data:
                return jsonify({'success': False, 'error': 'Invalid access code'}), 404
            file_data = result.data[0]
        
        return jsonify({
            'success': True,
            'data': {
                'original_filename': file_data['original_filename'],
                'file_size': file_data['file_size'],
                'owner_username': file_data.get('owner_username', 'Anonymous'),
                'expires_at': file_data['expires_at'],
                'created_at': file_data['created_at']
            }
        }), 200
    except Exception as e:
        logger.error(f"Error fetching file info: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch file info'}), 500

@app.route('/api/files/download/<access_code>', methods=['POST'])
@token_required
def download_file(payload, access_code):
    """
    Download file with triple security check:
    1. User must be authenticated (JWT token required)
    2. User must be owner OR in the intended recipients list (can_access_file)
    3. User must provide correct decryption key
    
    Even with access code and key, unauthorized users cannot download.
    """
    try:
        # Get decryption key from request body
        data = request.get_json()
        decryption_key = data.get('decryption_key', '').strip().upper()
        
        if not decryption_key:
            return jsonify({'success': False, 'error': 'Decryption key is required'}), 400
        
        username = payload['username']
        user_id = payload['user_id']
        
        if USE_LOCAL_STORAGE:
            if access_code not in local_files:
                return jsonify({'success': False, 'error': 'Invalid access code'}), 404
            
            file_info = local_files[access_code]
            
            # Check if user has access to this file
            if not can_access_file(access_code, username):
                logger.warning(f"Download attempt denied: {username} tried to access {access_code}")
                return jsonify({'success': False, 'error': 'Access denied: You are not authorized to download this file'}), 403
            
            # Get user's password hash and private key from database
            user_data = local_users.get(username)
            user_password_hash = user_data['password_hash']
            user_private_key_encrypted = user_data['private_key_encrypted']
            
            # Determine which encrypted key to use and sender's public key
            is_owner = file_info['owner_username'] == username
            if is_owner:
                # Owner is decrypting - sender is also owner, so use owner's public key
                owner_public_key = user_data['public_key']
                encrypted_key_data = {
                    'encrypted_key': file_info['encrypted_encryption_key']
                }
                sender_public_key = owner_public_key  # Self-encryption
            else:
                # Shared file - need to get sender's (owner's) public key
                owner_username = file_info['owner_username']
                owner_data = local_users.get(owner_username)
                sender_public_key = owner_data['public_key']
                
                # Find the shared file entry for this user
                user_shared = shared_files.get(username, [])
                shared_entry = next((f for f in user_shared if f['access_code'] == access_code), None)
                if not shared_entry:
                    return jsonify({'success': False, 'error': 'Shared file entry not found'}), 404
                encrypted_key_data = {
                    'encrypted_key': shared_entry['encrypted_key']
                }
            
            # Decrypt the encryption key using DH with sender's public key
            try:
                actual_encryption_key = DHEncryptionKeyManager.decrypt_key_with_private_key(
                    encrypted_key_data,
                    user_private_key_encrypted,
                    user_password_hash,
                    sender_public_key
                )
            except Exception as e:
                logger.error(f"Failed to decrypt encryption key: {str(e)}")
                return jsonify({'success': False, 'error': 'Invalid password or corrupted key'}), 400
            
            # Verify the provided decryption key matches
            if decryption_key != actual_encryption_key:
                logger.warning(f"Invalid decryption key for {access_code} by {username}")
                return jsonify({'success': False, 'error': 'Invalid decryption key'}), 400
            
            # Read encrypted file from disk
            encrypted_file_path = file_info['encrypted_file_path']
            if not os.path.exists(encrypted_file_path):
                return jsonify({'success': False, 'error': 'File not found or expired'}), 404
            
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt file
            derived_key = derive_key(decryption_key)
            cipher = Fernet(derived_key)
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
            except Exception as e:
                logger.error(f"Decryption failed for {access_code}: {str(e)}")
                return jsonify({'success': False, 'error': 'Decryption failed - invalid key or corrupted file'}), 400
            
            # Verify file integrity
            decrypted_hash = calculate_file_hash(decrypted_data)
            if decrypted_hash != file_info['file_hash']:
                return jsonify({'success': False, 'error': 'File integrity check failed - file may be corrupted'}), 400
            
            response = Response(
                decrypted_data,
                mimetype='application/octet-stream'
            )
            response.headers['Content-Disposition'] = f'attachment; filename="{file_info["filename"]}"'
            response.headers['Content-Length'] = str(len(decrypted_data))
            response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
            return response
        else:
            result = supabase.table('files').select('*').eq('access_code', access_code).execute()
            if not result.data:
                return jsonify({'success': False, 'error': 'Invalid access code'}), 404
            
            file_info = result.data[0]
            
            # Check if user has access to this file (owner or shared recipient)
            is_owner = file_info['owner_id'] == user_id
            
            # Check if file is shared with this user
            is_shared = False
            shared_entry = None
            if not is_owner:
                shares_result = supabase.table('file_shares').select('*').eq('file_id', file_info['id']).eq('shared_with_user_id', user_id).execute()
                is_shared = len(shares_result.data) > 0
                if is_shared:
                    shared_entry = shares_result.data[0]
            
            if not is_owner and not is_shared:
                return jsonify({'success': False, 'error': 'Access denied: You are not authorized to download this file'}), 403
            
            # Get user's password hash, private key, and public key from database
            user_result = supabase.table('users').select('password_hash, private_key_encrypted, public_key').eq('id', user_id).execute()
            if not user_result.data:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            user_password_hash = user_result.data[0]['password_hash']
            user_private_key_encrypted = user_result.data[0]['private_key_encrypted']
            user_public_key = user_result.data[0]['public_key']
            
            # Determine which encrypted key to use and get sender's public key
            if is_owner:
                # Owner is decrypting - sender is also owner
                encrypted_key_data = {
                    'encrypted_key': file_info['encrypted_encryption_key']
                }
                sender_public_key = user_public_key  # Self-encryption
            else:
                # Shared file - need owner's public key
                owner_result = supabase.table('users').select('public_key').eq('id', file_info['owner_id']).execute()
                if not owner_result.data:
                    return jsonify({'success': False, 'error': 'File owner not found'}), 404
                sender_public_key = owner_result.data[0]['public_key']
                
                encrypted_key_data = {
                    'encrypted_key': shared_entry['encrypted_key']
                }
            
            # Decrypt the encryption key using DH with sender's public key
            try:
                actual_encryption_key = DHEncryptionKeyManager.decrypt_key_with_private_key(
                    encrypted_key_data,
                    user_private_key_encrypted,
                    user_password_hash,
                    sender_public_key
                )
            except Exception as e:
                logger.error(f"Failed to decrypt encryption key: {str(e)}")
                return jsonify({'success': False, 'error': 'Invalid password or corrupted key'}), 400
            
            # Verify the provided decryption key matches
            if decryption_key != actual_encryption_key:
                return jsonify({'success': False, 'error': 'Invalid decryption key'}), 400
            
            storage_path = file_info['encrypted_file_path']
            
            encrypted_data = supabase.storage.from_(SUPABASE_BUCKET).download(storage_path)
            
            # Decrypt the file using the provided decryption key
            derived_key = derive_key(decryption_key)
            cipher = Fernet(derived_key)
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
            except Exception as e:
                return jsonify({'success': False, 'error': 'Decryption failed - invalid key or corrupted file'}), 400
            
            # Verify file integrity
            decrypted_hash = calculate_file_hash(decrypted_data)
            if decrypted_hash != file_info['file_hash']:
                return jsonify({'success': False, 'error': 'File integrity check failed'}), 400
            
            response = Response(
                decrypted_data,
                mimetype='application/octet-stream'
            )
            response.headers['Content-Disposition'] = f'attachment; filename="{file_info["filename"]}"'
            response.headers['Content-Length'] = str(len(decrypted_data))
            response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
            return response
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'success': False, 'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/files/my-files', methods=['GET', 'POST'])
@token_required
def get_my_files(payload):
    try:
        files = []
        
        # Get user's password hash and keys from database (no need for frontend to send password)
        user_password_hash = None
        user_private_key_encrypted = None
        user_public_key = None
        
        if USE_LOCAL_STORAGE:
            user_data = local_users.get(payload['username'])
            user_password_hash = user_data['password_hash']
            user_private_key_encrypted = user_data['private_key_encrypted']
            user_public_key = user_data['public_key']
        else:
            user_result = supabase.table('users').select('password_hash, private_key_encrypted, public_key').eq('id', payload['user_id']).execute()
            if user_result.data:
                user_password_hash = user_result.data[0]['password_hash']
                user_private_key_encrypted = user_result.data[0]['private_key_encrypted']
                user_public_key = user_result.data[0]['public_key']
        
        if USE_LOCAL_STORAGE:
            # Filter files by owner_id in local storage
            for access_code, file_info in local_files.items():
                if file_info.get('owner_id') == payload['user_id']:
                    encryption_key = file_info.get('encryption_key', '')
                    
                    # Try to decrypt if encrypted key exists
                    if user_password_hash and user_private_key_encrypted and user_public_key and not encryption_key and file_info.get('encrypted_encryption_key'):
                        try:
                            logger.info(f"Attempting to decrypt key for file {access_code}")
                            logger.info(f"Password hash length: {len(user_password_hash)}")
                            logger.info(f"Password hash starts with: {user_password_hash[:10]}")
                            encrypted_key_data = {
                                'encrypted_key': file_info['encrypted_encryption_key']
                            }
                            # Owner decrypting own file - use own public key
                            encryption_key = DHEncryptionKeyManager.decrypt_key_with_private_key(
                                encrypted_key_data, user_private_key_encrypted, user_password_hash, user_public_key
                            )
                            logger.info(f"Successfully decrypted key: {encryption_key}")
                        except Exception as e:
                            logger.error(f"Failed to decrypt encryption key for {access_code}: {str(e)}")
                            # Don't fail the entire request, just leave key empty
                            encryption_key = ''
                    
                    files.append({
                        'id': file_info.get('id', access_code),
                        'access_code': access_code,
                        'filename': file_info.get('filename', file_info.get('original_filename', 'Unknown')),
                        'size_mb': file_info.get('size_mb', file_info.get('file_size', 0)),
                        'timestamp': file_info.get('timestamp', file_info.get('created_at', '')),
                        'expiry_time': file_info.get('expiry_time', file_info.get('expires_at', '')),
                        'encryption_key': encryption_key
                    })
        else:
            result = supabase.table('files').select('*').eq('owner_id', payload['user_id']).execute()
            
            for file_info in result.data:
                encryption_key = file_info.get('encryption_key', '')
                
                # Try to decrypt if encrypted key exists
                if user_password_hash and user_private_key_encrypted and user_public_key and not encryption_key and file_info.get('encrypted_encryption_key'):
                    try:
                        encrypted_key_data = {
                            'encrypted_key': file_info['encrypted_encryption_key']
                        }
                        # Owner decrypting own file - use own public key
                        encryption_key = DHEncryptionKeyManager.decrypt_key_with_private_key(
                            encrypted_key_data, user_private_key_encrypted, user_password_hash, user_public_key
                        )
                    except Exception as e:
                        logger.error(f"Failed to decrypt encryption key: {str(e)}")
                        encryption_key = ''
                
                files.append({
                    'id': file_info['id'],
                    'access_code': file_info['access_code'],
                    'filename': file_info['filename'],
                    'size_mb': file_info['size_mb'],
                    'timestamp': file_info.get('created_at', ''),
                    'expiry_time': file_info.get('expiry_time', ''),
                    'encryption_key': encryption_key
                })
        
        return jsonify({'success': True, 'files': files}), 200
    except Exception as e:
        logger.error(f"Error fetching files: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch files'}), 500

@app.route('/api/files/shared-with-me', methods=['GET', 'POST'])
@token_required
def get_shared_files(payload):
    try:
        files = []
        username = payload['username']
        
        # Get user's password hash and private key from database
        user_password_hash = None
        user_private_key_encrypted = None
        if USE_LOCAL_STORAGE:
            user_data = local_users.get(username)
            user_password_hash = user_data['password_hash']
            user_private_key_encrypted = user_data['private_key_encrypted']
        else:
            user_result = supabase.table('users').select('password_hash, private_key_encrypted').eq('id', payload['user_id']).execute()
            if user_result.data:
                user_password_hash = user_result.data[0]['password_hash']
                user_private_key_encrypted = user_result.data[0]['private_key_encrypted']
        
        if USE_LOCAL_STORAGE:
            # Get files shared with current user
            user_shared_files = shared_files.get(username, [])
            
            for shared_file in user_shared_files:
                access_code = shared_file['access_code']
                # Try to get filename from shared_file first, then from local_files
                filename = shared_file.get('filename', 'Unknown')
                size_mb = 0
                decryption_key = shared_file.get('decryption_key', '')
                
                # Try to decrypt if encrypted key exists
                if user_password_hash and user_private_key_encrypted and not decryption_key and shared_file.get('encrypted_key'):
                    try:
                        # Get sender's public key
                        sender_username = shared_file.get('sender')
                        if sender_username and sender_username in local_users:
                            sender_public_key = local_users[sender_username]['public_key']
                            encrypted_key_data = {
                                'encrypted_key': shared_file['encrypted_key']
                            }
                            decryption_key = DHEncryptionKeyManager.decrypt_key_with_private_key(
                                encrypted_key_data, user_private_key_encrypted, user_password_hash, sender_public_key
                            )
                    except Exception as e:
                        logger.error(f"Failed to decrypt shared file key: {str(e)}")
                        decryption_key = ''
                
                # Get additional file details from local_files if available
                if access_code in local_files:
                    file_info = local_files[access_code]
                    if filename == 'Unknown':
                        filename = file_info.get('filename', 'Unknown')
                    size_mb = file_info.get('size_mb', 0)
                
                files.append({
                    'access_code': access_code,
                    'filename': filename,
                    'sender': shared_file.get('sender', 'Unknown'),
                    'timestamp': shared_file.get('timestamp', ''),
                    'decryption_key': decryption_key,
                    'size_mb': size_mb
                })
        else:
            user_id = payload['user_id']
            shares_result = supabase.table('file_shares').select('*').eq('shared_with_user_id', user_id).execute()
            
            file_ids = [share['file_id'] for share in shares_result.data]
            # Create a map of file_id to encrypted_key from file_shares
            file_share_data = {
                share['file_id']: share.get('encrypted_key', '')
                for share in shares_result.data
            }
            
            if file_ids:
                files_result = supabase.table('files').select('*').in_('id', file_ids).execute()
                
                for file_info in files_result.data:
                    # Get owner's username and public key
                    owner_result = supabase.table('users').select('username, public_key').eq('id', file_info['owner_id']).execute()
                    sender_name = owner_result.data[0]['username'] if owner_result.data else 'Unknown'
                    sender_public_key = owner_result.data[0].get('public_key', '') if owner_result.data else ''
                    
                    decryption_key = file_info.get('encryption_key', '')
                    
                    # Try to decrypt if encrypted key exists
                    file_id = file_info['id']
                    encrypted_key_from_share = file_share_data.get(file_id, '')
                    
                    if user_password_hash and user_private_key_encrypted and sender_public_key and not decryption_key and encrypted_key_from_share:
                        try:
                            encrypted_key_data = {
                                'encrypted_key': encrypted_key_from_share
                            }
                            decryption_key = DHEncryptionKeyManager.decrypt_key_with_private_key(
                                encrypted_key_data, user_private_key_encrypted, user_password_hash, sender_public_key
                            )
                        except Exception as e:
                            logger.error(f"Failed to decrypt shared file key: {str(e)}")
                            decryption_key = ''
                    
                    files.append({
                        'access_code': file_info['access_code'],
                        'filename': file_info['filename'],
                        'sender': sender_name,
                        'timestamp': file_info.get('created_at', ''),
                        'decryption_key': decryption_key,
                        'size_mb': file_info.get('size_mb', 0)
                    })
        
        return jsonify({'success': True, 'files': files}), 200
    except Exception as e:
        logger.error(f"Error fetching shared files: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch shared files'}), 500

@app.route('/api/files/shared/<access_code>', methods=['DELETE'])
@token_required
def remove_shared_file(payload, access_code):
    """Remove a shared file from current user's shared list only"""
    try:
        username = payload['username']
        
        if USE_LOCAL_STORAGE:
            if username in shared_files:
                # Remove the file from this user's shared list
                original_count = len(shared_files[username])
                shared_files[username] = [f for f in shared_files[username] 
                                         if f.get('access_code') != access_code]
                
                if len(shared_files[username]) < original_count:
                    # Also remove user from file_shares list
                    if access_code in file_shares and username in file_shares[access_code]['shared_with']:
                        file_shares[access_code]['shared_with'].remove(username)
                    
                    logger.info(f"User {username} removed shared file {access_code} from their list")
                    return jsonify({'success': True, 'message': 'File removed from your shared list'}), 200
                else:
                    return jsonify({'success': False, 'error': 'File not found in your shared list'}), 404
            else:
                return jsonify({'success': False, 'error': 'No shared files found'}), 404
        else:
            user_id = payload['user_id']
            
            # Get the file_id from access_code
            file_result = supabase.table('files').select('id').eq('access_code', access_code).execute()
            
            if not file_result.data:
                return jsonify({'success': False, 'error': 'File not found'}), 404
            
            file_id = file_result.data[0]['id']
            
            # Delete the file_share entry for this user
            delete_result = supabase.table('file_shares').delete().eq('file_id', file_id).eq('shared_with_user_id', user_id).execute()
            
            if delete_result.data:
                return jsonify({'success': True, 'message': 'File removed from your shared list'}), 200
            else:
                return jsonify({'success': False, 'error': 'File not found in your shared list'}), 404
        
    except Exception as e:
        logger.error(f"Error removing shared file: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to remove shared file'}), 500

@app.route('/api/files/<file_id>', methods=['DELETE'])
@token_required
def delete_file(payload, file_id):
    try:
        if USE_LOCAL_STORAGE:
            # Find file by id in local storage
            file_to_delete = None
            access_code_to_delete = None
            for access_code, file_info in local_files.items():
                if file_info.get('id') == file_id or access_code == file_id:
                    file_to_delete = file_info
                    access_code_to_delete = access_code
                    break
            
            if not file_to_delete:
                return jsonify({'success': False, 'error': 'File not found'}), 404
            
            if file_to_delete['owner_id'] != payload['user_id']:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Delete the encrypted file from disk
            file_path = file_to_delete.get('encrypted_file_path')
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted file from disk: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting file from disk: {str(e)}")
            
            if access_code_to_delete in file_shares:
                del file_shares[access_code_to_delete]
            
            for username in shared_files:
                shared_files[username] = [f for f in shared_files[username] 
                                         if f.get('access_code') != access_code_to_delete]
            
            del local_files[access_code_to_delete]
        else:
            result = supabase.table('files').select('*').eq('id', file_id).execute()
            
            if not result.data:
                return jsonify({'success': False, 'error': 'File not found'}), 404
            
            file_info = result.data[0]
            
            if file_info['owner_id'] != payload['user_id']:
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            storage_path = file_info['encrypted_file_path']
            supabase.storage.from_(SUPABASE_BUCKET).remove([storage_path])
            supabase.table('files').delete().eq('id', file_id).execute()
        
        return jsonify({'success': True, 'message': 'File deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Delete error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete file'}), 500

@app.route('/api/users/list', methods=['GET'])
@token_required
def list_users(payload):
    try:
        result = supabase.table('users').select('id, username').execute()
        
        users = [{'id': u['id'], 'username': u['username']} for u in result.data if u['username'] != payload['username']]
        
        return jsonify({'success': True, 'users': users}), 200
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch users'}), 500

def cleanup_expired_files():
    if not USE_LOCAL_STORAGE and supabase:
        try:
            result = supabase.table('files').select('id, encrypted_file_path').lt('expiry_time', datetime.now().isoformat()).execute()
            
            for file_info in result.data:
                try:
                    supabase.storage.from_(SUPABASE_BUCKET).remove([file_info['encrypted_file_path']])
                    supabase.table('files').delete().eq('id', file_info['id']).execute()
                    logger.info(f"Cleaned up expired file: {file_info['id']}")
                except Exception as e:
                    logger.error(f"Error cleaning up file {file_info['id']}: {str(e)}")
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
    elif USE_LOCAL_STORAGE:
        try:
            current_time = datetime.now()
            expired_codes = [code for code, file_data in local_files.items() 
                           if 'expires_at' in file_data and datetime.fromisoformat(file_data['expires_at']) < current_time]
            for code in expired_codes:
                file_data = local_files[code]
                file_path = file_data.get('encrypted_file_path')
                if file_path and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        logger.info(f"Deleted expired file from disk: {file_path}")
                    except Exception as e:
                        logger.error(f"Error deleting expired file from disk: {str(e)}")
                
                del local_files[code]
                if code in file_shares:
                    del file_shares[code]
                logger.info(f"Cleaned up expired file with code: {code}")
        except Exception as e:
            logger.error(f"Local cleanup error: {str(e)}")

def cleanup_worker():
    while True:
        cleanup_expired_files()
        time.sleep(3600)

cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
cleanup_thread.start()

def _pregen_dh_parameters():
    try:
        logger.info("Background DH parameter pre-generation started")
        DiffieHellmanManager.get_dh_parameters()
        logger.info("Background DH parameter pre-generation finished")
    except Exception as e:
        logger.error(f"DH pre-generation error: {str(e)}")

dh_pregen_thread = threading.Thread(target=_pregen_dh_parameters, daemon=True)
dh_pregen_thread.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Secure File Transfer API on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
