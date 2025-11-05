# Security Fix Deployment Guide

## Overview
This update fixes a **critical security vulnerability** where file encryption keys were stored in plain text in the database. Now, encryption keys are properly encrypted using each user's Diffie-Hellman public key.

## What Changed

### Backend Changes (api.py)
1. **New `EncryptionKeyManager` class** - Handles encryption/decryption of file encryption keys
2. **File Upload** - Encrypts the encryption key with owner's public key before storing
3. **File Sharing** - Encrypts the encryption key separately for each recipient using their public key
4. **File Download** - Requires user's password to decrypt their private key, then uses it to decrypt the encryption key

### Database Schema Changes
**Files table** - Added new columns:
- `encrypted_encryption_key` (TEXT) - The file's encryption key, encrypted with owner's public key
- `ephemeral_public_key` (TEXT) - Ephemeral public key used in the key exchange

**File_shares table** - Added new columns:
- `encrypted_key` (TEXT) - The file's encryption key, encrypted with recipient's public key
- `ephemeral_public_key` (TEXT) - Ephemeral public key used in the key exchange

### Frontend Changes (download.html)
- Added password field for file downloads
- Updated API call to send user's password along with decryption key

## Deployment Steps

### Step 1: Update Supabase Database Schema

1. Go to your Supabase dashboard: https://supabase.com/dashboard
2. Select your project
3. Go to **SQL Editor**
4. Run this SQL migration:

```sql
-- Add new columns to files table
ALTER TABLE files 
ADD COLUMN IF NOT EXISTS encrypted_encryption_key TEXT,
ADD COLUMN IF NOT EXISTS ephemeral_public_key TEXT;

-- Add new columns to file_shares table
ALTER TABLE file_shares
ADD COLUMN IF NOT EXISTS encrypted_key TEXT,
ADD COLUMN IF NOT EXISTS ephemeral_public_key TEXT;

-- IMPORTANT: Clear existing data (old unencrypted format is incompatible)
DELETE FROM file_shares;
DELETE FROM files;
```

**⚠️ WARNING**: This will delete all existing files! The old files use unencrypted keys and are incompatible with the new system.

### Step 2: Push Code to GitHub

```powershell
cd d:\CAPSTONE\Deepseek
git add .
git commit -m "Security fix: Encrypt file encryption keys with user public keys"
git push origin main
```

### Step 3: Railway will Auto-Deploy

Railway will automatically detect the push and redeploy your backend with the new security fixes.

### Step 4: Vercel will Auto-Deploy Frontend

Vercel will automatically redeploy the frontend with the new password field.

### Step 5: Test the Security Fix

1. **Register a new user** at https://capstone-frontend-iota-rouge.vercel.app
2. **Upload a file** with an encryption key
3. **Download the file**:
   - Enter access code
   - Enter decryption key
   - **Enter your account password** (new requirement)
4. **Share a file** with another user
5. **Have the recipient download** - they'll need their own password

## How It Works Now

### Upload Flow
1. User uploads file → File encrypted with random key
2. Random key encrypted with **user's public key** → Stored in DB as `encrypted_encryption_key`
3. If shared, key also encrypted with each **recipient's public key** → Stored in `file_shares`

### Download Flow
1. User provides: access code, decryption key, **their password**
2. Backend uses password to decrypt user's **private key**
3. Private key used to decrypt the **encrypted encryption key**
4. Decrypted encryption key used to decrypt the file
5. File sent to user

## Security Benefits

✅ **Database compromise**: Attacker cannot decrypt files without users' passwords
✅ **End-to-end encryption**: Only file owner and intended recipients can decrypt
✅ **Per-recipient keys**: Each user gets their own encrypted copy of the encryption key
✅ **DiffieHellman properly utilized**: Uses ephemeral key exchange for forward secrecy

## Breaking Changes

⚠️ **All existing files must be deleted** - Old format incompatible
⚠️ **Users must enter password on download** - New security requirement
⚠️ **Frontend updated** - New password field in download form

## Troubleshooting

### "Invalid password or corrupted key"
- User entered wrong account password
- Private key is corrupted

### "Shared file entry not found"
- File not properly shared (file_shares entry missing)
- Database migration not complete

### "Failed to decrypt encryption key"
- Ephemeral public key missing
- Encrypted key corrupted

## Rollback (If Needed)

If you need to rollback:
```powershell
git revert HEAD
git push origin main
```

Then manually remove the new columns from Supabase:
```sql
ALTER TABLE files DROP COLUMN encrypted_encryption_key, DROP COLUMN ephemeral_public_key;
ALTER TABLE file_shares DROP COLUMN encrypted_key, DROP COLUMN ephemeral_public_key;
```

---

**Status**: Ready to deploy ✅
**Breaking**: Yes - requires database wipe ⚠️
**Security Impact**: Critical security improvement 🔐
