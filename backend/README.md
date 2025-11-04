# Backend - Secure File Transfer API# Backend API - Secure File Transfer System



Flask-based REST API for secure encrypted file transfer with Supabase integration.Flask REST API backend with Supabase integration for secure file transfer with end-to-end encryption.



## 🚀 Quick Start## Features



### Prerequisites- RESTful API architecture

- Python 3.11+- JWT-based authentication

- Supabase account- Supabase database integration

- Virtual environment (recommended)- Supabase Storage for encrypted files

- CORS enabled for frontend

### Local Development- End-to-end encryption

- Diffie-Hellman key exchange

1. **Install Dependencies**

   ```bash## Tech Stack

   cd backend

   pip install -r requirements.txt- **Framework**: Flask

   ```- **Database**: Supabase (PostgreSQL)

- **Storage**: Supabase Storage

2. **Configure Environment**- **Authentication**: JWT tokens

   ```bash- **Encryption**: Cryptography library (Fernet, DH)

   # Copy example env file

   cp .env.example .env## API Endpoints

   

   # Edit .env with your credentials### Authentication

   ```- `POST /api/auth/signup` - Create new user account

- `POST /api/auth/login` - Login and get JWT token

3. **Run Server**- `POST /api/auth/logout` - Logout user

   ```bash- `GET /api/auth/me` - Get current user info

   python api.py

   ```### Files

   - `POST /api/files/upload` - Upload and encrypt file

   Server runs on `http://localhost:5000`- `GET /api/files/download/<access_code>` - Download file

- `GET /api/files/my-files` - Get user's uploaded files

## 🔧 Environment Variables- `GET /api/files/shared-files` - Get files shared with user

- `DELETE /api/files/<file_id>` - Delete file

Required variables in `.env`:

### Sharing

```env- `POST /api/files/share` - Share file with users

SECRET_KEY=your-random-secret-key-here- `GET /api/files/shared-with/<file_id>` - Get users file is shared with

JWT_SECRET_KEY=your-jwt-secret-key-here

SUPABASE_URL=https://your-project.supabase.co### Users

SUPABASE_KEY=your-supabase-anon-key- `GET /api/users/search?q=<username>` - Search for users

SUPABASE_BUCKET=encrypted-files- `GET /api/users/list` - List all users (for sharing)

USE_LOCAL_STORAGE=false

FRONTEND_URL=http://localhost:3000## Installation

```

### Prerequisites

**Get Supabase credentials:**- Python 3.9+

1. Go to https://supabase.com/dashboard- Supabase account

2. Select your project

3. Go to Settings → API### Setup

4. Copy URL and anon/public key

1. **Install dependencies**:

## 📚 API Endpoints   ```bash

   pip install -r requirements.txt

### Authentication   ```

- `POST /api/signup` - Register new user

- `POST /api/login` - Login and get JWT token2. **Configure environment variables**:

- `GET /api/users` - List all users (requires auth)   ```bash

   cp .env.example .env

### File Operations   ```

- `POST /api/files/upload` - Upload encrypted file   Edit `.env` and add your Supabase credentials:

- `POST /api/files/download/<code>` - Download file   ```

- `GET /api/files/my-files` - Get uploaded files   SECRET_KEY=your-secret-key

- `GET /api/files/shared-with-me` - Get received files   JWT_SECRET_KEY=your-jwt-secret

- `DELETE /api/files/<id>` - Delete file (owner)   SUPABASE_URL=https://your-project.supabase.co

- `DELETE /api/files/shared/<code>` - Remove from shared list   SUPABASE_SERVICE_KEY=your-service-key

   SUPABASE_BUCKET=encrypted-files

### System   FRONTEND_URL=http://localhost:3000

- `GET /api/health` - Health check   ```

- `GET /api/` - API info

3. **Set up Supabase**:

## 🔐 Security Features   - Run `supabase_schema.sql` in Supabase SQL Editor

   - Create storage bucket: `encrypted-files`

- **Password Hashing**: Bcrypt with salt

- **JWT Authentication**: Token-based auth4. **Run the server**:

- **File Encryption**: AES-256 (Fernet)   ```bash

- **Key Derivation**: PBKDF2   python app.py

- **File Integrity**: SHA-256 hash verification   ```

- **Access Control**: Owner/recipient validation   Server runs on `http://localhost:5000`



## 📦 Dependencies## API Documentation



- **Flask 3.0** - Web framework### Authentication

- **Supabase 2.9** - Database & storage

- **Cryptography 41.0** - AES encryption#### POST /api/auth/signup

- **PyJWT 2.8** - JWT tokensCreate a new user account.

- **Bcrypt 4.1** - Password hashing

- **Gunicorn 21.2** - Production server**Request Body**:

```json

## 🚀 Deployment{

  "username": "user123",

### Deploy to Render  "password": "Pass1234"

}

1. **Push to GitHub**```

   ```bash

   git add .**Response** (201 Created):

   git commit -m "Ready for deployment"```json

   git push{

   ```  "success": true,

  "message": "User created successfully"

2. **Create Web Service on Render**}

   - Go to https://dashboard.render.com```

   - New → Web Service

   - Connect GitHub repo#### POST /api/auth/login

   - Root Directory: `backend`Login and receive JWT token.

   - Build Command: `pip install -r requirements.txt`

   - Start Command: `gunicorn api:app --bind 0.0.0.0:$PORT --workers 4 --timeout 120`**Request Body**:

```json

3. **Add Environment Variables** (in Render dashboard){

   - All variables from `.env` file  "username": "user123",

   - Don't use `.env` file in production  "password": "Pass1234"

}

### Deploy to Other Platforms```



See main [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) for:**Response** (200 OK):

- Heroku```json

- Railway{

- AWS  "success": true,

- Google Cloud  "token": "eyJhbGc...",

  "user": {

## 🧪 Testing    "id": "uuid",

    "username": "user123"

```bash  }

# Check if server is running}

curl http://localhost:5000/api/health```



# Test signup### Files

curl -X POST http://localhost:5000/api/signup \

  -H "Content-Type: application/json" \#### POST /api/files/upload

  -d '{"username":"test","password":"test123"}'Upload and encrypt a file.



# Test login**Headers**:

curl -X POST http://localhost:5000/api/login \```

  -H "Content-Type: application/json" \Authorization: Bearer <token>

  -d '{"username":"test","password":"test123"}'Content-Type: multipart/form-data

``````



## 📁 Project Structure**Request Body** (multipart/form-data):

- `file`: File to upload

```- `recipients`: Comma-separated usernames (optional)

backend/- `encryption_key`: 6-character key (optional, auto-generated if not provided)

├── api.py              # Main Flask application

├── requirements.txt    # Python dependencies**Response** (201 Created):

├── Procfile           # Deployment config (Render/Heroku)```json

├── .env.example       # Environment template{

├── .env               # Your environment (not in git)  "success": true,

├── .gitignore         # Git ignore rules  "access_code": "A3X9K2",

└── uploads/           # Local storage (dev only)  "encryption_key": "B7Y4M1",

```  "filename": "document.pdf",

  "size_mb": 2.5

## 🐛 Troubleshooting}

```

### Server won't start

- Check Python version: `python --version` (need 3.11+)#### GET /api/files/download/<access_code>

- Verify dependencies: `pip list`Download and decrypt a file.

- Check `.env` file exists and has correct values

**Headers**:

### Database errors```

- Verify Supabase credentialsAuthorization: Bearer <token>

- Check RLS policies are configured```

- Ensure tables exist (run setup SQL)

**Query Parameters**:

### CORS errors- `decryption_key`: 6-character decryption key

- Update `FRONTEND_URL` in environment variables

- Must match exact frontend URL (no trailing slash)**Response** (200 OK):

- File download (binary data)

### File upload fails

- Check Supabase storage bucket exists## Configuration

- Verify storage policies configured

- Check file size (max 150MB)### Environment Variables



## 📄 License| Variable | Description | Required |

|----------|-------------|----------|

MIT License - See main LICENSE file| `SECRET_KEY` | Flask secret key | Yes |

| `JWT_SECRET_KEY` | JWT token secret | Yes |

## 🔗 Related| `SUPABASE_URL` | Supabase project URL | Yes |

| `SUPABASE_SERVICE_KEY` | Supabase service role key | Yes |

- [Frontend README](../frontend/README.md)| `SUPABASE_BUCKET` | Storage bucket name | Yes |

- [Main README](../README.md)| `FRONTEND_URL` | Frontend URL for CORS | Yes |

- [Deployment Guide](../DEPLOYMENT_GUIDE.md)| `PORT` | Server port (default: 5000) | No |


### CORS Configuration

The API allows requests from the frontend URL specified in `FRONTEND_URL` environment variable.

## Security

- JWT tokens expire after 24 hours
- Passwords hashed with bcrypt
- Files encrypted with Fernet (AES-256)
- Diffie-Hellman key exchange for sharing
- Row Level Security in Supabase
- Private storage buckets

## Deployment

### Railway

1. Push code to GitHub
2. Connect repository to Railway
3. Add environment variables
4. Deploy

### Render

1. Create new Web Service
2. Connect GitHub repository
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add environment variables

### Heroku

```bash
heroku create your-app-name
heroku config:set SECRET_KEY=xxx JWT_SECRET_KEY=xxx SUPABASE_URL=xxx ...
git push heroku master
```

## Development

### Running locally
```bash
python app.py
```

### Running with Gunicorn
```bash
gunicorn app:app --bind 0.0.0.0:5000 --workers 4
```

## Error Handling

All errors return JSON with this format:
```json
{
  "success": false,
  "error": "Error message"
}
```

Status codes:
- 200: Success
- 201: Created
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 500: Internal Server Error

## Testing

Test the API with curl:

```bash
# Signup
curl -X POST http://localhost:5000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser123","password":"Test1234"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser123","password":"Test1234"}'

# Upload file (replace TOKEN)
curl -X POST http://localhost:5000/api/files/upload \
  -H "Authorization: Bearer TOKEN" \
  -F "file=@test.pdf" \
  -F "recipients=otheruser"
```

## License

Educational purpose - Capstone Project

## Support

See main project documentation for detailed setup instructions.
