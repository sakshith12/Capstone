# 🔐 Secure File Transfer System# 🔐 Secure File Transfer System



A modern, end-to-end encrypted file sharing platform built with Flask and vanilla JavaScript. Share files securely with unique access codes and encryption keys, powered by Diffie-Hellman key exchange and AES-256 encryption.A secure, encrypted file transfer application with end-to-end encryption, built with Flask (Backend) and vanilla JavaScript (Frontend), powered by Supabase.



![Project Status](https://img.shields.io/badge/status-active-success.svg)## ✨ Features

![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)

![Flask Version](https://img.shields.io/badge/flask-3.0-green.svg)- **🔒 End-to-End Encryption**: Files encrypted with AES-256 using Fernet

![License](https://img.shields.io/badge/license-MIT-blue.svg)- **👥 User Authentication**: JWT-based secure authentication

- **📤 File Sharing**: Share files with specific users or broadcast to all

## 🌟 Features- **⏰ Auto-Expiry**: Files automatically expire after 7 days

- **🎯 Access Control**: Only authorized recipients can download files

### Core Features- **📊 Dashboard**: View sent and received files

- ✅ **End-to-End Encryption**: Files encrypted with AES-256-CBC before upload- **☁️ Cloud Storage**: Supabase storage for scalable file hosting

- 🔑 **Diffie-Hellman Key Exchange**: Secure key sharing between users without transmitting encryption keys- **🔐 File Integrity**: SHA-256 hash verification on download

- 👥 **User Authentication**: JWT-based authentication with bcrypt password hashing

- 📤 **File Upload & Download**: Encrypted file storage with automatic expiry## 🚀 Tech Stack

- 🤝 **File Sharing**: Share encrypted files with specific users securely

- 📊 **Dashboard**: Manage uploaded and shared files### Backend

- ⏰ **Auto-Expiry**: Files automatically deleted after configurable time periods (24h, 3d, 7d)- **Flask 3.0** - Python web framework

- 🔒 **Access Control**: Triple security check (JWT token + user authorization + decryption key)- **Supabase** - PostgreSQL database + file storage

- **Cryptography** - AES-256 encryption (Fernet)

### Security Features- **PyJWT** - JWT token authentication

- **Password Security**: - **Bcrypt** - Password hashing

  - Bcrypt hashing (10 rounds) with unique salt per user

  - Never stores plain passwords### Frontend

  - Password hash used to encrypt user's private DH key- **Vanilla JavaScript** - No frameworks, pure JS

  - **HTML5/CSS3** - Modern, responsive UI

- **Encryption Layers**:- **Fetch API** - RESTful API communication

  - User passwords → Bcrypt hash (never stored plain)

  - Private DH keys → AES-256 encrypted with password hash### Database

  - File encryption keys → DH-encrypted for each recipient- **PostgreSQL** (via Supabase) - Relational database

  - Files → AES-256 encrypted with derived keys (PBKDF2 + 100k iterations)- **Row Level Security (RLS)** - Database-level access control



- **Key Features**:## 📁 Project Structure

  - 2048-bit Diffie-Hellman parameters

  - SHA-256 for file integrity verification```

  - HKDF for key derivation from DH shared secretsDeepseek/

  - Per-user encrypted key storage (no shared secrets in database)├── backend/

│   ├── api.py              # Main Flask application

## 📋 Table of Contents│   ├── requirements.txt    # Python dependencies

│   ├── Procfile           # Deployment configuration

- [Architecture](#-architecture)│   └── .env               # Environment variables (not in git)

- [Installation](#-installation)├── frontend/

- [Configuration](#-configuration)│   ├── index.html         # Login page

- [Usage](#-usage)│   ├── signup.html        # Registration page

- [API Documentation](#-api-documentation)│   ├── dashboard.html     # User dashboard

- [Security Model](#-security-model)│   ├── send.html          # File upload/sharing

- [Project Structure](#-project-structure)│   ├── download.html      # File download

- [Deployment](#-deployment)│   └── static/

- [Documentation](#-documentation)│       └── js/

- [Known Issues](#-known-issues)│           ├── api.js     # API wrapper

- [Contributing](#-contributing)│           └── config.js  # Configuration

├── supabase_setup.sql     # Database schema

## 🏗️ Architecture├── storage_policies.sql   # Storage bucket policies

└── DEPLOYMENT_GUIDE.md    # Deployment instructions

### Technology Stack```



**Backend:**## 🛠️ Local Development Setup

- Flask 3.0 (Python web framework)

- SQLite/Supabase (Database)### Prerequisites

- Cryptography library (AES, DH, bcrypt)- Python 3.11+

- JWT for authentication- Supabase account

- Python cryptography for encryption operations- Git



**Frontend:**### Backend Setup

- HTML5, CSS3, JavaScript (Vanilla)

- Responsive design```bash

- Session storage for token management# Navigate to backend

cd backend

### System Architecture

# Create virtual environment

```python -m venv venv

┌─────────────────┐

│   Web Browser   │# Activate virtual environment

│   (Frontend)    │# Windows:

└────────┬────────┘venv\Scripts\activate

         │ HTTPS# Linux/Mac:

         ▼source venv/bin/activate

┌─────────────────┐

│   Flask API     │# Install dependencies

│  (Backend)      │pip install -r requirements.txt

├─────────────────┤

│ Authentication  │# Create .env file

│ File Manager    │copy .env.example .env

│ DH Encryption   │

└────────┬────────┘# Edit .env with your Supabase credentials

         │# Get them from: https://supabase.com/dashboard/project/YOUR_PROJECT/settings/api

    ┌────┴────┐

    ▼         ▼# Run the server

┌────────┐ ┌──────────┐python api.py

│Database│ │ Storage  │```

│(Users, │ │(Encrypted│

│ Keys)  │ │  Files)  │Backend will run on `http://localhost:5000`

└────────┘ └──────────┘

```### Frontend Setup



### Encryption Flow```bash

# Navigate to frontend

```cd frontend

1. Upload:

   File → AES Encrypt → Storage# Start a simple HTTP server

   Encryption Key → DH Encrypt → Database# Python:

python -m http.server 3000

2. Share:

   Get Key (DH Decrypt with Owner's keys)# Or Node.js:

   Key → DH Encrypt with Recipient's Public Key → Databasenpx http-server -p 3000

```

3. Download:

   DH Decrypt Key (with Recipient's keys)Frontend will run on `http://localhost:3000`

   Download Encrypted File

   AES Decrypt File → Original File### Supabase Setup

```

1. Create a Supabase project at https://supabase.com

## 🚀 Installation2. Run `supabase_setup.sql` in SQL Editor

3. Create storage bucket named `encrypted-files`

### Prerequisites4. Run `storage_policies.sql` in SQL Editor

5. Copy your project URL and anon key to `.env`

- Python 3.11 or higher

- pip (Python package manager)## 🔒 Security Features

- Git

1. **Password Security**

### Step 1: Clone Repository   - Bcrypt hashing with salt

   - Never stored in plain text

```bash

git clone https://github.com/sakshith12/Capstone.git2. **File Encryption**

cd Capstone   - AES-256 encryption using Fernet

```   - Unique encryption key per file

   - PBKDF2 key derivation

### Step 2: Install Backend Dependencies

3. **Access Control**

```bash   - JWT token authentication

cd backend   - Server-side access validation

pip install -r requirements.txt   - Owner and recipient verification

```

4. **File Integrity**

**Backend Dependencies:**   - SHA-256 hash verification

```   - Detects file corruption or tampering

flask==3.0.0

flask-cors==4.0.05. **Auto Cleanup**

cryptography==41.0.7   - Files expire after 7 days

bcrypt==4.1.2   - Automatic cleanup job

pyjwt==2.8.0

python-dotenv==1.0.0## 📝 Environment Variables

supabase==2.3.0

``````env

# Backend (.env)

### Step 3: Configure Environment VariablesSECRET_KEY=your-secret-key

JWT_SECRET_KEY=your-jwt-secret

Create a `.env` file in the `backend/` directory:SUPABASE_URL=https://your-project.supabase.co

SUPABASE_KEY=your-supabase-anon-key

```bashSUPABASE_BUCKET=encrypted-files

# Backend ConfigurationUSE_LOCAL_STORAGE=false

SECRET_KEY=your-secret-key-change-in-productionFRONTEND_URL=http://localhost:3000

JWT_SECRET_KEY=your-jwt-secret-change-in-production```

FRONTEND_URL=http://localhost:8000

## 🚀 Deployment

# Storage Configuration (choose one)

USE_LOCAL_STORAGE=trueSee [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed deployment instructions.



# Supabase Configuration (if USE_LOCAL_STORAGE=false)**Quick Deploy:**

SUPABASE_URL=https://your-project-id.supabase.co- Backend: Render, Heroku, or Railway

SUPABASE_KEY=your-supabase-anon-key- Frontend: Vercel, Netlify, or Render

SUPABASE_BUCKET=encrypted-files- Database: Supabase (already configured)



# File Settings## 📊 Database Schema

MAX_FILE_SIZE_MB=150

```### Users Table

- `id` (BIGSERIAL) - Primary key

### Step 4: Initialize Database- `username` (TEXT) - Unique username

- `password_hash` (TEXT) - Bcrypt hashed password

If using Supabase, run the schema:- `public_key`, `dh_parameters`, `private_key_encrypted` (TEXT) - Future encryption keys

- `created_at` (TIMESTAMP) - Account creation time

```bash

# Execute backend/supabase_schema_update.sql in your Supabase SQL editor### Files Table

```- `id` (BIGSERIAL) - Primary key

- `access_code` (TEXT) - Unique 6-character code

If using local storage, the system will automatically create necessary directories.- `filename` (TEXT) - Original filename

- `owner_id` (BIGINT) - User who uploaded

## ⚙️ Configuration- `encrypted_file_path` (TEXT) - Storage path

- `encryption_key` (TEXT) - File encryption key

### Environment Variables- `file_hash` (TEXT) - SHA-256 hash

- `size_mb` (DECIMAL) - File size

| Variable | Description | Default | Required |- `expiry_time` (TIMESTAMP) - Auto-delete time

|----------|-------------|---------|----------|- `created_at` (TIMESTAMP) - Upload time

| `SECRET_KEY` | Flask secret key for sessions | - | Yes |

| `JWT_SECRET_KEY` | JWT token signing key | - | Yes |### File Shares Table

| `JWT_EXPIRATION_HOURS` | JWT token validity period | 24 | No |- `id` (BIGSERIAL) - Primary key

| `USE_LOCAL_STORAGE` | Use local file system instead of cloud | false | No |- `file_id` (BIGINT) - Reference to files

| `MAX_FILE_SIZE_MB` | Maximum file upload size | 150 | No |- `shared_with_user_id` (BIGINT) - Recipient user

| `SUPABASE_URL` | Supabase project URL | - | If not local |- `shared_at` (TIMESTAMP) - Share time

| `SUPABASE_KEY` | Supabase API key | - | If not local |

| `SUPABASE_BUCKET` | Storage bucket name | encrypted-files | No |## 🎯 API Endpoints



### Security Settings### Authentication

- `POST /api/signup` - Register new user

Edit `backend/api.py` to customize:- `POST /api/login` - User login

- `GET /api/users` - List all users (for sharing)

```python

# Password validation### Files

MIN_PASSWORD_LENGTH = 8- `POST /api/files/upload` - Upload and encrypt file

MAX_PASSWORD_LENGTH = 20- `POST /api/files/download/<code>` - Download and decrypt file

- `GET /api/files/my-files` - Get user's uploaded files

# Bcrypt rounds (higher = more secure but slower)- `GET /api/files/shared-with-me` - Get files shared with user

BCRYPT_ROUNDS = 10- `DELETE /api/files/<id>` - Delete file (owner only)

- `DELETE /api/files/shared/<code>` - Remove from shared list

# DH parameters

DH_KEY_SIZE = 2048  # bits## 🐛 Troubleshooting



# PBKDF2 iterations### Backend won't start

PBKDF2_ITERATIONS = 100000- Check Python version (3.11+)

```- Verify all dependencies installed

- Check `.env` file exists and has correct values

## 📖 Usage

### Frontend can't connect to backend

### Starting the Application- Verify backend is running on port 5000

- Check `config.js` has correct API_BASE_URL

#### Start Backend Server- Check browser console for CORS errors



```bash### Files won't upload

cd backend- Check Supabase storage bucket exists

python api.py- Verify storage policies are configured

```- Check file size (max 150MB)



Server runs on: `http://localhost:5000`### Can't download files

- Verify correct access code and decryption key

#### Start Frontend Server- Check user has access (owner or recipient)

- Verify file hasn't expired

```bash

cd frontend## 📄 License

python -m http.server 8000

```MIT License - See LICENSE file for details



Frontend available at: `http://localhost:8000`## 👥 Contributing



### User WorkflowPull requests welcome! Please ensure:

- Code follows existing style

#### 1. Registration- All tests pass

- Security best practices maintained

1. Navigate to `http://localhost:8000/signup.html`

2. Enter username (8-20 characters, alphanumeric + underscore)## 🔗 Links

3. Enter password (8-20 characters, must contain letter + number)

4. System generates:- [Supabase Documentation](https://supabase.com/docs)

   - Bcrypt password hash- [Flask Documentation](https://flask.palletsprojects.com/)

   - DH key pair (2048-bit)- [Cryptography Library](https://cryptography.io/)

   - Encrypts private key with password hash

5. User account created## 📧 Support



#### 2. LoginFor issues and questions, please open a GitHub issue.



1. Navigate to `http://localhost:8000/index.html`---

2. Enter credentials

3. System verifies with bcryptBuilt with ❤️ using Flask, Supabase, and vanilla JavaScript

4. Receives JWT token (valid 24 hours)
5. Redirected to dashboard

#### 3. Upload File

1. Go to Dashboard → Upload section
2. Select file (max 150 MB)
3. Optional: Enter custom 6-character encryption key
4. Select expiry time (24h / 3d / 7d)
5. Click "Upload & Encrypt"
6. Receive:
   - Access Code (e.g., `ABC123`)
   - Encryption Key (e.g., `X9Y2K5`)
7. Share these codes with recipients

#### 4. Share File

1. Go to Dashboard → My Files
2. Click "Share" on desired file
3. Enter recipient usernames (comma-separated)
4. System encrypts file key for each recipient using DH
5. Recipients can now access the file

#### 5. Download File

1. Navigate to Download page
2. Enter Access Code and Decryption Key
3. System verifies access and decrypts file
4. Original file downloaded

## 📡 API Documentation

### Authentication Endpoints

#### POST `/api/auth/signup`
Register new user account.

**Request:**
```json
{
  "username": "john_doe",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully"
}
```

#### POST `/api/auth/login`
Authenticate user and get JWT token.

**Request:**
```json
{
  "username": "john_doe",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid",
    "username": "john_doe"
  }
}
```

### File Endpoints

#### POST `/api/files/upload`
Upload and encrypt file.

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
Content-Type: multipart/form-data
```

**Form Data:**
```
file: <file_binary>
encryption_key: "A3X9K2" (optional)
expiry_hours: 24 (optional)
```

**Response:**
```json
{
  "success": true,
  "access_code": "ABC123",
  "encryption_key": "X9Y2K5",
  "file_id": "uuid"
}
```

#### POST `/api/files/download/<access_code>`
Download and decrypt file.

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json
```

**Request:**
```json
{
  "decryption_key": "X9Y2K5"
}
```

**Response:**
```
Binary file data with Content-Disposition header
```

#### POST `/api/files/my-files`
Get list of user's uploaded files with decrypted keys.

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{
  "success": true,
  "files": [
    {
      "id": "uuid",
      "filename": "document.pdf",
      "access_code": "ABC123",
      "encryption_key": "X9Y2K5",
      "size_mb": 2.5,
      "created_at": "2025-11-09T10:00:00Z",
      "expiry_time": "2025-11-10T10:00:00Z"
    }
  ]
}
```

#### POST `/api/files/shared-with-me`
Get list of files shared with user.

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{
  "success": true,
  "files": [
    {
      "access_code": "DEF456",
      "filename": "report.docx",
      "sender": "alice",
      "decryption_key": "Y7K3M9",
      "size_mb": 1.2,
      "shared_at": "2025-11-09T11:00:00Z"
    }
  ]
}
```

#### DELETE `/api/files/<file_id>`
Delete uploaded file.

**Headers:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{
  "success": true,
  "message": "File deleted successfully"
}
```

## 🔒 Security Model

### Multi-Layer Encryption

#### Layer 1: Password Security
```
User Password → bcrypt.hashpw(password, salt)
              → $2b$10$N9qo8uLO... (60 chars)
              → Stored in database
```

#### Layer 2: Private Key Protection
```
DH Private Key → AES-256 encrypt with password_hash
               → Base64 encoded
               → Stored in database
```

#### Layer 3: File Encryption Key Protection
```
File Encryption Key ("X9Y2K5")
  → Owner: DH encrypt with (owner_private × owner_public)
  → Recipient: DH encrypt with (owner_private × recipient_public)
  → Different encrypted version for each user
  → Stored in database
```

#### Layer 4: File Data Encryption
```
File Data → PBKDF2 derive key from "X9Y2K5" (100k iterations)
          → AES-256-CBC encrypt
          → Stored in storage
```

### Access Control

**Triple Verification:**
1. **Authentication**: Valid JWT token required
2. **Authorization**: User must be owner or shared recipient
3. **Knowledge**: User must know the 6-character decryption key

### Key Security Properties

- **Forward Secrecy**: Each file has unique encryption key
- **No Key Reuse**: DH shared secret derived per user pair
- **Integrity Verification**: SHA-256 hash checked on download
- **Zero-Knowledge**: Server never knows decryption keys in plaintext
- **Unique Salts**: Each password gets unique bcrypt salt

## 📁 Project Structure

```
d:\CAPSTONE\Deepseek\
│
├── backend/
│   ├── api.py                          # Main Flask application (1625 lines)
│   ├── requirements.txt                # Python dependencies
│   └── uploads/                        # Local file storage (if USE_LOCAL_STORAGE=true)
│
├── frontend/
│   ├── index.html                      # Login page
│   ├── signup.html                     # Registration page
│   ├── dashboard.html                  # File management dashboard
│   ├── send.html                       # File upload page
│   ├── download.html                   # File download page
│   │
│   └── static/
│       ├── css/
│       │   └── style.css               # Styles
│       │
│       └── js/
│           ├── config.js               # API configuration
│           └── api.js                  # API client library
│
├── docs/
│   ├── COMPLETE_ENCRYPTION_GUIDE.md    # Full encryption documentation
│   ├── PROJECT_CODE_FLOW.md            # Code flow documentation
│   └── PASSWORD_HASH_UPDATE.md         # Security update documentation
│
├── .env                                 # Environment variables (create this)
├── .gitignore                           # Git ignore rules
├── README.md                            # This file
└── requirements.txt                     # Root dependencies
```

### Key Files

- **`backend/api.py`**: Core Flask application with all endpoints
- **`frontend/static/js/api.js`**: Frontend API client
- **`frontend/index.html`**: Login/authentication page
- **`frontend/dashboard.html`**: Main user interface
- **`docs/COMPLETE_ENCRYPTION_GUIDE.md`**: Detailed encryption explanation

## 🌐 Deployment

### Local Development

Already covered in [Usage](#-usage) section.

### Production Deployment

#### Using Render.com (Recommended)

1. **Fork this repository**

2. **Create Render account**: https://render.com

3. **Create Web Service**:
   - Connect GitHub repository
   - Build Command: `cd backend && pip install -r requirements.txt`
   - Start Command: `cd backend && python api.py`
   - Add environment variables from `.env`

4. **Create Static Site for Frontend**:
   - Connect same repository
   - Publish Directory: `frontend`
   - Update `frontend/static/js/config.js` with backend URL

5. **Configure Supabase**:
   - Create project at https://supabase.com
   - Run SQL schema from `backend/supabase_schema_update.sql`
   - Create storage bucket named `encrypted-files`
   - Update environment variables

#### Environment Variables for Production

```bash
SECRET_KEY=<strong-random-key>
JWT_SECRET_KEY=<strong-random-key>
USE_LOCAL_STORAGE=false
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-key-here
SUPABASE_BUCKET=encrypted-files
MAX_FILE_SIZE_MB=150
FRONTEND_URL=https://your-frontend.onrender.com
```

### Security Considerations for Production

1. **Use HTTPS**: Always use HTTPS in production
2. **Strong Keys**: Generate strong SECRET_KEY and JWT_SECRET_KEY
3. **CORS**: Configure proper CORS origins
4. **Rate Limiting**: Implement rate limiting on API endpoints
5. **File Size Limits**: Adjust MAX_FILE_SIZE_MB based on needs
6. **Monitoring**: Set up logging and monitoring
7. **Backups**: Regular database and file backups

## 📚 Documentation

Comprehensive documentation available in the `docs/` directory:

- **[COMPLETE_ENCRYPTION_GUIDE.md](docs/COMPLETE_ENCRYPTION_GUIDE.md)**: 
  - Detailed explanation of all encryption mechanisms
  - DH key exchange mathematics
  - Security analysis and threat model
  
- **[PROJECT_CODE_FLOW.md](docs/PROJECT_CODE_FLOW.md)**:
  - Step-by-step code execution flow
  - From registration to file download
  - Includes code snippets and sequence diagrams

- **[PASSWORD_HASH_UPDATE.md](docs/PASSWORD_HASH_UPDATE.md)**:
  - Security improvement documentation
  - Password hash authentication changes

## 🐛 Known Issues & Limitations

### Current Issues

1. **Old User Account Migration**:
   - **Issue**: Users created before the latest security update cannot decrypt their files
   - **Cause**: Private keys were encrypted using old method (incompatible with current architecture)
   - **Error**: "Bad decrypt. Incorrect password?" when trying to access files
   - **Workaround**: Create a new user account for testing
   - **Permanent Solution**: Migration script needed to re-encrypt old private keys with new method

### Limitations

- **File Size**: Maximum 150 MB per file (configurable)
- **Browser Compatibility**: Requires modern browser with Crypto API support
- **Session Storage**: Encrypted files require re-authentication after 24 hours (JWT expiry)
- **Concurrent Uploads**: Limited to one file upload at a time per user

### Planned Fixes

- Migration script for old user accounts
- Database indexing for faster lookups
- Improved error messages for encryption failures
- Rate limiting on authentication endpoints

## 🔮 Future Enhancements

- [ ] Multi-file upload support
- [ ] Folder/directory upload
- [ ] File preview for images/PDFs
- [ ] Email notifications for file shares
- [ ] QR code generation for access codes
- [ ] Two-factor authentication (2FA)
- [ ] File versioning
- [ ] Audit logs
- [ ] Mobile app (React Native)
- [ ] End-to-end encrypted chat
- [ ] Progressive Web App (PWA)
- [ ] Docker containerization

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide for Python code
- Add comments for complex logic
- Update documentation for API changes
- Test thoroughly before submitting PR
- Include security considerations for new features

## 📄 License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2025 Sakshith

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 👨‍💻 Author

**Sakshith**
- GitHub: [@sakshith12](https://github.com/sakshith12)
- Repository: [Capstone](https://github.com/sakshith12/Capstone)

## 🙏 Acknowledgments

- Flask team for the excellent web framework
- Python Cryptography library maintainers
- Supabase for backend infrastructure
- All contributors and testers

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation in `/docs` folder
- Review code comments in `backend/api.py`

---

**⚠️ Security Note**: This is an educational project demonstrating end-to-end encryption concepts. While it implements strong cryptographic practices, it should undergo professional security audit before use in production environments with sensitive data.

**Last Updated**: November 9, 2025
