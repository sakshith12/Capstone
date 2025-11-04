# Deployment Guide - Secure File Transfer

## Prerequisites
- GitHub account
- Render account (free tier available)
- Vercel/Netlify account (optional, for frontend)
- Supabase project already configured ✅

---

## Option 1: Deploy Everything on Render (Recommended - Easiest)

### Step 1: Push Code to GitHub

```bash
cd d:\CAPSTONE\Deepseek
git init
git add .
git commit -m "Initial commit - Ready for deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/deepseek-file-transfer.git
git push -u origin main
```

### Step 2: Deploy Backend on Render

1. Go to https://dashboard.render.com/
2. Click **New +** → **Web Service**
3. Connect your GitHub repository
4. Configure:
   - **Name**: `deepseek-backend`
   - **Root Directory**: `backend`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn api:app --bind 0.0.0.0:$PORT --workers 4 --timeout 120`

5. Add Environment Variables:
   ```
   SECRET_KEY=<generate-random-string>
   JWT_SECRET_KEY=<generate-random-string>
   SUPABASE_URL=https://neeqxhqjkyrlkudwtbcx.supabase.co
   SUPABASE_KEY=<your-supabase-anon-key>
   SUPABASE_BUCKET=encrypted-files
   USE_LOCAL_STORAGE=false
   FRONTEND_URL=https://deepseek-frontend.onrender.com
   ```

6. Click **Create Web Service**
7. Wait for deployment (5-10 minutes)
8. **Copy the backend URL** (e.g., `https://deepseek-backend.onrender.com`)

### Step 3: Update Frontend Config

1. Edit `frontend/static/js/config.js`:
   ```javascript
   API_BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
       ? 'http://localhost:5000'
       : 'https://deepseek-backend.onrender.com', // YOUR ACTUAL BACKEND URL
   ```

2. Commit and push:
   ```bash
   git add .
   git commit -m "Update backend URL"
   git push
   ```

### Step 4: Deploy Frontend on Render

1. In Render Dashboard, click **New +** → **Static Site**
2. Connect same GitHub repository
3. Configure:
   - **Name**: `deepseek-frontend`
   - **Root Directory**: `frontend`
   - **Build Command**: `echo "No build needed"`
   - **Publish Directory**: `.`

4. Click **Create Static Site**
5. Wait for deployment
6. **Copy the frontend URL** (e.g., `https://deepseek-frontend.onrender.com`)

### Step 5: Update Backend CORS

1. Go back to your backend service settings
2. Update Environment Variable:
   ```
   FRONTEND_URL=https://deepseek-frontend.onrender.com
   ```
3. Redeploy backend

### Step 6: Test Production

1. Visit your frontend URL
2. Create a test account
3. Upload a file
4. Share with another user
5. Download and verify

---

## Option 2: Deploy Frontend on Vercel (Alternative)

### Deploy Frontend to Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
cd d:\CAPSTONE\Deepseek
vercel --prod

# Follow prompts and select "frontend" as root directory
```

**Or use Vercel Dashboard:**
1. Go to https://vercel.com/dashboard
2. Click **Add New** → **Project**
3. Import your GitHub repository
4. Configure:
   - **Root Directory**: `frontend`
   - **Build Command**: Leave empty
   - **Output Directory**: `.`
5. Deploy

---

## Option 3: Deploy Frontend on Netlify

1. Go to https://app.netlify.com/
2. Click **Add new site** → **Import from Git**
3. Connect GitHub repository
4. Configure:
   - **Base directory**: `frontend`
   - **Build command**: Leave empty
   - **Publish directory**: `frontend`
5. Click **Deploy site**

---

## Post-Deployment Checklist

✅ Backend deployed and running
✅ Frontend deployed and accessible
✅ Environment variables configured
✅ CORS settings updated with production frontend URL
✅ Supabase connection working
✅ File upload/download tested
✅ User registration/login tested
✅ File sharing tested

---

## Troubleshooting

### Backend Issues

**500 Error - Check Logs:**
```bash
# In Render dashboard → Your service → Logs
```

**CORS Error:**
- Verify `FRONTEND_URL` environment variable matches your actual frontend URL
- Must include `https://` and no trailing slash

**Database Error:**
- Verify Supabase credentials in environment variables
- Check RLS policies are configured
- Verify storage bucket exists

### Frontend Issues

**API Connection Failed:**
- Check `config.js` has correct backend URL
- Verify backend is running (visit backend URL in browser)
- Check browser console for CORS errors

**Files Not Uploading:**
- Check file size (max 150MB)
- Verify Supabase storage policies
- Check backend logs

---

## Free Tier Limits

**Render (Free Tier):**
- Backend spins down after 15 min inactivity (cold starts ~30s)
- 750 hours/month
- Sufficient for testing and demos

**Vercel (Free Tier):**
- 100 GB bandwidth/month
- Unlimited sites
- Instant global CDN

**Netlify (Free Tier):**
- 100 GB bandwidth/month
- 300 build minutes/month

**Supabase (Free Tier):**
- 500 MB database
- 1 GB file storage
- 2 GB bandwidth

---

## Need Help?

- Render Docs: https://render.com/docs
- Vercel Docs: https://vercel.com/docs
- Supabase Docs: https://supabase.com/docs

---

## Environment Variables Reference

### Backend (.env)
```
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here
SUPABASE_URL=https://neeqxhqjkyrlkudwtbcx.supabase.co
SUPABASE_KEY=your-supabase-anon-key
SUPABASE_BUCKET=encrypted-files
USE_LOCAL_STORAGE=false
FRONTEND_URL=https://your-frontend-url.com
```

### Security Notes
- Never commit `.env` file to Git
- Use strong random strings for SECRET_KEY and JWT_SECRET_KEY
- Keep Supabase keys secure
- Use HTTPS in production (automatically provided by Render/Vercel/Netlify)
