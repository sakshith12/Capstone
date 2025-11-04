# 🔐 Secure File Transfer System

A secure, encrypted file transfer application with end-to-end encryption, built with Flask (Backend) and vanilla JavaScript (Frontend), powered by Supabase.

## ✨ Features

- **🔒 End-to-End Encryption**: Files encrypted with AES-256 using Fernet
- **👥 User Authentication**: JWT-based secure authentication
- **📤 File Sharing**: Share files with specific users or broadcast to all
- **⏰ Auto-Expiry**: Files automatically expire after 7 days
- **🎯 Access Control**: Only authorized recipients can download files
- **📊 Dashboard**: View sent and received files
- **☁️ Cloud Storage**: Supabase storage for scalable file hosting
- **🔐 File Integrity**: SHA-256 hash verification on download

## 🚀 Tech Stack

### Backend
- **Flask 3.0** - Python web framework
- **Supabase** - PostgreSQL database + file storage
- **Cryptography** - AES-256 encryption (Fernet)
- **PyJWT** - JWT token authentication
- **Bcrypt** - Password hashing

### Frontend
- **Vanilla JavaScript** - No frameworks, pure JS
- **HTML5/CSS3** - Modern, responsive UI
- **Fetch API** - RESTful API communication

### Database
- **PostgreSQL** (via Supabase) - Relational database
- **Row Level Security (RLS)** - Database-level access control

## 📁 Project Structure

```
Deepseek/
├── backend/
│   ├── api.py              # Main Flask application
│   ├── requirements.txt    # Python dependencies
│   ├── Procfile           # Deployment configuration
│   └── .env               # Environment variables (not in git)
├── frontend/
│   ├── index.html         # Login page
│   ├── signup.html        # Registration page
│   ├── dashboard.html     # User dashboard
│   ├── send.html          # File upload/sharing
│   ├── download.html      # File download
│   └── static/
│       └── js/
│           ├── api.js     # API wrapper
│           └── config.js  # Configuration
├── supabase_setup.sql     # Database schema
├── storage_policies.sql   # Storage bucket policies
└── DEPLOYMENT_GUIDE.md    # Deployment instructions
```

## 🛠️ Local Development Setup

### Prerequisites
- Python 3.11+
- Supabase account
- Git

### Backend Setup

```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
copy .env.example .env

# Edit .env with your Supabase credentials
# Get them from: https://supabase.com/dashboard/project/YOUR_PROJECT/settings/api

# Run the server
python api.py
```

Backend will run on `http://localhost:5000`

### Frontend Setup

```bash
# Navigate to frontend
cd frontend

# Start a simple HTTP server
# Python:
python -m http.server 3000

# Or Node.js:
npx http-server -p 3000
```

Frontend will run on `http://localhost:3000`

### Supabase Setup

1. Create a Supabase project at https://supabase.com
2. Run `supabase_setup.sql` in SQL Editor
3. Create storage bucket named `encrypted-files`
4. Run `storage_policies.sql` in SQL Editor
5. Copy your project URL and anon key to `.env`

## 🔒 Security Features

1. **Password Security**
   - Bcrypt hashing with salt
   - Never stored in plain text

2. **File Encryption**
   - AES-256 encryption using Fernet
   - Unique encryption key per file
   - PBKDF2 key derivation

3. **Access Control**
   - JWT token authentication
   - Server-side access validation
   - Owner and recipient verification

4. **File Integrity**
   - SHA-256 hash verification
   - Detects file corruption or tampering

5. **Auto Cleanup**
   - Files expire after 7 days
   - Automatic cleanup job

## 📝 Environment Variables

```env
# Backend (.env)
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
SUPABASE_BUCKET=encrypted-files
USE_LOCAL_STORAGE=false
FRONTEND_URL=http://localhost:3000
```

## 🚀 Deployment

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed deployment instructions.

**Quick Deploy:**
- Backend: Render, Heroku, or Railway
- Frontend: Vercel, Netlify, or Render
- Database: Supabase (already configured)

## 📊 Database Schema

### Users Table
- `id` (BIGSERIAL) - Primary key
- `username` (TEXT) - Unique username
- `password_hash` (TEXT) - Bcrypt hashed password
- `public_key`, `dh_parameters`, `private_key_encrypted` (TEXT) - Future encryption keys
- `created_at` (TIMESTAMP) - Account creation time

### Files Table
- `id` (BIGSERIAL) - Primary key
- `access_code` (TEXT) - Unique 6-character code
- `filename` (TEXT) - Original filename
- `owner_id` (BIGINT) - User who uploaded
- `encrypted_file_path` (TEXT) - Storage path
- `encryption_key` (TEXT) - File encryption key
- `file_hash` (TEXT) - SHA-256 hash
- `size_mb` (DECIMAL) - File size
- `expiry_time` (TIMESTAMP) - Auto-delete time
- `created_at` (TIMESTAMP) - Upload time

### File Shares Table
- `id` (BIGSERIAL) - Primary key
- `file_id` (BIGINT) - Reference to files
- `shared_with_user_id` (BIGINT) - Recipient user
- `shared_at` (TIMESTAMP) - Share time

## 🎯 API Endpoints

### Authentication
- `POST /api/signup` - Register new user
- `POST /api/login` - User login
- `GET /api/users` - List all users (for sharing)

### Files
- `POST /api/files/upload` - Upload and encrypt file
- `POST /api/files/download/<code>` - Download and decrypt file
- `GET /api/files/my-files` - Get user's uploaded files
- `GET /api/files/shared-with-me` - Get files shared with user
- `DELETE /api/files/<id>` - Delete file (owner only)
- `DELETE /api/files/shared/<code>` - Remove from shared list

## 🐛 Troubleshooting

### Backend won't start
- Check Python version (3.11+)
- Verify all dependencies installed
- Check `.env` file exists and has correct values

### Frontend can't connect to backend
- Verify backend is running on port 5000
- Check `config.js` has correct API_BASE_URL
- Check browser console for CORS errors

### Files won't upload
- Check Supabase storage bucket exists
- Verify storage policies are configured
- Check file size (max 150MB)

### Can't download files
- Verify correct access code and decryption key
- Check user has access (owner or recipient)
- Verify file hasn't expired

## 📄 License

MIT License - See LICENSE file for details

## 👥 Contributing

Pull requests welcome! Please ensure:
- Code follows existing style
- All tests pass
- Security best practices maintained

## 🔗 Links

- [Supabase Documentation](https://supabase.com/docs)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Cryptography Library](https://cryptography.io/)

## 📧 Support

For issues and questions, please open a GitHub issue.

---

Built with ❤️ using Flask, Supabase, and vanilla JavaScript
