# Frontend - Secure File Transfer

Modern, responsive web interface for secure encrypted file sharing.

## 🚀 Quick Start

### Local Development

1. **Navigate to frontend**
   ```bash
   cd frontend
   ```

2. **Start Development Server**

   **Option 1: Python**
   ```bash
   python -m http.server 3000
   ```

   **Option 2: Node.js**
   ```bash
   npx http-server -p 3000
   ```

   **Option 3: VS Code Live Server**
   - Install "Live Server" extension
   - Right-click `index.html` → Open with Live Server

3. **Open Browser**
   ```
   http://localhost:3000
   ```

## 🔧 Configuration

Edit `static/js/config.js`:

```javascript
const CONFIG = {
    API_BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:5000'                     // Local development
        : 'https://your-backend.onrender.com',        // Production
    MAX_FILE_SIZE: 150 * 1024 * 1024, // 150MB
    ALLOWED_EXTENSIONS: ['pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'rar', 'mp3', 'mp4']
};
```

**Auto-detects environment** - No changes needed for deployment!

## 📁 Project Structure

```
frontend/
├── index.html              # Login page
├── signup.html             # Registration page
├── dashboard.html          # User dashboard
├── send.html              # File upload/share
├── download.html          # File download
├── .gitignore
└── static/
    ├── css/
    │   └── style.css      # Shared styles
    └── js/
        ├── api.js         # API wrapper
        ├── auth.js        # Authentication utilities
        ├── config.js      # Configuration
        ├── dashboard.js   # Dashboard logic
        ├── download.js    # Download logic
        └── upload.js      # Upload logic
```

## 🎨 Pages Overview

### 🔐 index.html (Login)
- User authentication
- JWT token management
- Redirect to dashboard on success

### 📝 signup.html (Registration)
- New user registration
- Password validation
- Auto-login after signup

### 📊 dashboard.html
- View sent files
- View received files
- Download files
- Delete files (owner)
- Remove shared files (recipient)

### 📤 send.html
- File upload with drag-drop
- Multiple file support
- Recipient selection
- "Send to All" feature
- Progress indicators

### 📥 download.html
- Enter access code
- Enter decryption key
- File integrity verification
- Auto-download on success

## 🎯 Features

### User Experience
- ✅ Responsive design (mobile-friendly)
- ✅ Drag-and-drop file upload
- ✅ Real-time progress indicators
- ✅ Flash messages for feedback
- ✅ Auto-redirect after actions
- ✅ Clean, modern UI

### Security
- ✅ JWT token storage (localStorage)
- ✅ Auto-logout on invalid token
- ✅ Access code + decryption key required
- ✅ File integrity verification
- ✅ Secure file handling

### File Management
- ✅ Multiple file selection
- ✅ File type validation
- ✅ Size limit enforcement (150MB)
- ✅ Download with original filename
- ✅ File expiry information

## 🚀 Deployment

### Deploy to Vercel (Recommended)

1. **Install Vercel CLI**
   ```bash
   npm install -g vercel
   ```

2. **Deploy**
   ```bash
   cd frontend
   vercel --prod
   ```

3. **Configure**
   - Follow prompts
   - Set root as `frontend` directory
   - No build command needed

4. **Update Backend URL**
   - After deployment, copy your Vercel URL
   - Update backend's `FRONTEND_URL` environment variable

### Deploy to Netlify

1. **Via CLI**
   ```bash
   npm install -g netlify-cli
   cd frontend
   netlify deploy --prod
   ```

2. **Via Dashboard**
   - Go to https://app.netlify.com
   - New site from Git
   - Base directory: `frontend`
   - Build command: (leave empty)
   - Publish directory: `frontend`

### Deploy to Render (Static Site)

1. **Create Static Site**
   - Go to https://dashboard.render.com
   - New → Static Site
   - Connect GitHub repo
   - Root Directory: `frontend`
   - Build Command: `echo "No build needed"`
   - Publish Directory: `.`

2. **Deploy**
   - Click "Create Static Site"
   - Wait for deployment

## 🔄 Update Production API URL

After deploying backend, update `config.js`:

```javascript
API_BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5000'
    : 'https://your-actual-backend.onrender.com',  // ← Update this
```

Commit and redeploy:
```bash
git add .
git commit -m "Update production API URL"
git push
```

## 🧪 Testing

### Local Testing Checklist
- [ ] Login with valid credentials
- [ ] Register new user
- [ ] Upload file (single)
- [ ] Upload multiple files
- [ ] Share with specific user
- [ ] Send to all users
- [ ] View sent files in dashboard
- [ ] View received files in dashboard
- [ ] Download file with code + key
- [ ] Delete own file
- [ ] Remove shared file

### Production Testing
- [ ] HTTPS working
- [ ] CORS configured correctly
- [ ] API calls successful
- [ ] File upload/download working
- [ ] Dashboard loads correctly

## 🎨 Customization

### Change Colors
Edit `static/css/style.css`:
```css
:root {
    --primary-color: #667eea;      /* Main brand color */
    --secondary-color: #764ba2;     /* Hover states */
    --background: #f4f7f6;          /* Page background */
    --card-bg: white;               /* Card background */
}
```

### Change Max File Size
Edit `static/js/config.js`:
```javascript
MAX_FILE_SIZE: 150 * 1024 * 1024, // Change to desired size in bytes
```

### Add File Types
Edit `static/js/config.js`:
```javascript
ALLOWED_EXTENSIONS: ['pdf', 'jpg', 'png', 'your-type'],
```

## 🐛 Troubleshooting

### Can't login
- Check backend is running
- Verify API_BASE_URL in config.js
- Check browser console for errors
- Clear localStorage and try again

### CORS errors
- Verify backend's FRONTEND_URL matches your URL exactly
- Check browser console for specific CORS error
- Ensure backend has flask-cors installed

### Files won't upload
- Check file size (max 150MB)
- Verify file extension is allowed
- Check backend logs for errors
- Verify Supabase storage configured

### Dashboard not loading files
- Check JWT token is valid (localStorage)
- Verify API endpoints responding
- Check browser network tab
- Try logout and login again

## 📱 Browser Support

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+
- ⚠️ IE 11 (not supported)

## 📄 License

MIT License - See main LICENSE file

## 🔗 Related

- [Backend README](../backend/README.md)
- [Main README](../README.md)
- [Deployment Guide](../DEPLOYMENT_GUIDE.md)

## 💡 Tips

- Use Chrome DevTools for debugging
- Check Network tab for API calls
- Monitor Console for JavaScript errors
- Use Incognito mode to test fresh sessions
- Clear cache if changes don't appear
