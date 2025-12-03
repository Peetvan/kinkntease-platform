-- THREE NEW FEATURES DATABASE SETUP
-- 1. Photo Locking
-- 2. Block/Ignore Users  
-- 3. Read Receipts

-- ====================
-- 1. PHOTO LOCKING
-- ====================

-- Add is_locked column to user_photos
ALTER TABLE user_photos ADD COLUMN is_locked TINYINT(1) DEFAULT 0 AFTER is_primary;

-- Create photo access requests table (for locked photos)
CREATE TABLE IF NOT EXISTS photo_access_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    photo_id INT NOT NULL,
    requester_id INT NOT NULL,
    status ENUM('pending', 'approved', 'denied') DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP NULL,
    UNIQUE KEY unique_request (photo_id, requester_id),
    INDEX idx_photo_id (photo_id),
    INDEX idx_requester (requester_id),
    INDEX idx_status (status)
);

-- ====================
-- 2. BLOCK/IGNORE USERS
-- ====================

-- Create blocked_users table
CREATE TABLE IF NOT EXISTS blocked_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    blocker_id INT NOT NULL,
    blocked_id INT NOT NULL,
    reason VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_block (blocker_id, blocked_id),
    INDEX idx_blocker (blocker_id),
    INDEX idx_blocked (blocked_id)
);

-- ====================
-- 3. READ RECEIPTS
-- ====================

-- Add read_at timestamp to messages table
ALTER TABLE messages ADD COLUMN read_at TIMESTAMP NULL AFTER is_read;

-- Update existing read messages with timestamp
UPDATE messages SET read_at = created_at WHERE is_read = 1 AND read_at IS NULL;

-- ====================
-- VERIFICATION QUERIES
-- ====================

-- Check photo locking
DESCRIBE user_photos;

-- Check access requests table
DESCRIBE photo_access_requests;

-- Check blocked users table
DESCRIBE blocked_users;

-- Check read receipts
DESCRIBE messages;

-- Test queries
SELECT COUNT(*) as locked_photos FROM user_photos WHERE is_locked = 1;
SELECT COUNT(*) as blocked_users FROM blocked_users;
SELECT COUNT(*) as read_messages FROM messages WHERE is_read = 1;

-- Ignore "Duplicate column" or "Table exists" errors - that means they're already set up!
