-- Migration: Add DH-based encryption key support using permanent user keys
-- This updates the schema to use Diffie-Hellman public key cryptography
-- Each user's permanent DH keys are used (no ephemeral keys needed!)

-- Step 1: Add encrypted_encryption_key column to files table
ALTER TABLE files 
ADD COLUMN IF NOT EXISTS encrypted_encryption_key TEXT;

-- Step 2: Add encrypted_key column to file_shares table
ALTER TABLE file_shares
ADD COLUMN IF NOT EXISTS encrypted_key TEXT;

-- Step 3: (Optional) Remove old encryption_key column after data migration
-- WARNING: This will delete the old encryption keys!
-- Only run this after you've re-uploaded all files with the new system
-- ALTER TABLE files DROP COLUMN encryption_key;

-- Step 4: Remove ephemeral_public_key columns if they exist (no longer needed)
-- ALTER TABLE files DROP COLUMN IF EXISTS ephemeral_public_key;
-- ALTER TABLE file_shares DROP COLUMN IF EXISTS ephemeral_public_key;

-- Note: You'll need to clear all existing files and file_shares records
-- as they use the old unencrypted key system:
DELETE FROM file_shares;
DELETE FROM files;
