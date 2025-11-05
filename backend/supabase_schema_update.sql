-- Migration: Add encrypted encryption key support
-- This updates the schema to store encryption keys encrypted with user's public keys
-- instead of storing them in plain text

-- Step 1: Add new column to files table
ALTER TABLE files 
ADD COLUMN IF NOT EXISTS encrypted_encryption_key TEXT;

-- Step 2: Add new column to file_shares table
ALTER TABLE file_shares
ADD COLUMN IF NOT EXISTS encrypted_key TEXT;

-- Step 3: (Optional) Remove old encryption_key column after data migration
-- WARNING: This will delete the old encryption keys!
-- Only run this after you've re-uploaded all files with the new system
-- ALTER TABLE files DROP COLUMN encryption_key;

-- Note: You'll need to clear all existing files and file_shares records
-- as they use the old unencrypted key system:
-- DELETE FROM file_shares;
-- DELETE FROM files;
