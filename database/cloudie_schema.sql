-- ============================================================
-- Cloudie Database Schema
-- Secure Cloud Storage with AI Malware Analyzer and AES Encryption
-- Based on ERD in Chapter 3 of the thesis
--
-- Updated 2026-10-12 to match the live app: includes the columns and
-- table that includes/db.php adds at runtime (folders, files.folder_id,
-- files.verdict, email verification + login OTP on authentication).
-- db.php still runs those migrations idempotently, so this file and an
-- older database both end up with the same structure.
-- ============================================================

CREATE DATABASE IF NOT EXISTS cloudie_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cloudie_db;

-- ------------------------------------------------------------
-- USER table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id        INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(64)  NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    email          VARCHAR(120) NOT NULL UNIQUE,
    phone_num      VARCHAR(20)  NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- AUTHENTICATION table (one-to-one with USER)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authentication (
    auth_id     INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    email       VARCHAR(120) NOT NULL,
    token       VARCHAR(255) NULL,
    last_login  DATETIME NULL,
    email_verified TINYINT(1)   NOT NULL DEFAULT 0,
    verify_token   VARCHAR(64)  NULL,
    otp_hash       VARCHAR(255) NULL,      -- hash of the 6-digit login OTP
    otp_expires    DATETIME     NULL,
    otp_attempts   TINYINT      NOT NULL DEFAULT 0,
    CONSTRAINT fk_auth_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- FOLDER table (user-created folders for organising files)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS folders (
    folder_id   INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    folder_name VARCHAR(100) NOT NULL,
    color       VARCHAR(20)  NOT NULL DEFAULT 'cyan',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    KEY idx_folder_user (user_id),
    CONSTRAINT fk_folder_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- FILE table
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS files (
    file_id        INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    file_name      VARCHAR(255) NOT NULL,
    stored_name    VARCHAR(255) NOT NULL,    -- name on disk (encrypted blob)
    file_type      VARCHAR(50)  NOT NULL,
    file_size      BIGINT NOT NULL,
    file_md5       VARCHAR(32)  NOT NULL,    -- MD5 of original (pre-encryption)
    is_clean       TINYINT(1) DEFAULT 1,     -- legacy flag: 1 = stored, 0 = rejected
    verdict        VARCHAR(20) NULL DEFAULT NULL, -- clean | suspicious | malicious (VT primary, RF supporting)
    scan_report    TEXT NULL,                -- JSON report from the analyzer (VT + RF)
    folder_id      INT NULL DEFAULT NULL,
    uploaded_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_files_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_file_folder FOREIGN KEY (folder_id)
        REFERENCES folders(folder_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- KEY table (one-to-one with FILE)
-- AES key is stored hashed; the user keeps the real key (QR/text).
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_keys (
    key_id       INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT NOT NULL,
    file_id      INT NOT NULL UNIQUE,
    key_hash     VARCHAR(255) NOT NULL,    -- sha256(raw AES key); the real key is never stored
    iv_b64       VARCHAR(64)  NOT NULL,    -- base64 IV used for AES-CBC
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_keys_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_keys_file FOREIGN KEY (file_id)
        REFERENCES files(file_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- ACTION table (audit log)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS actions (
    act_id     INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    file_id    INT NULL,
    key_id     INT NULL,
    act_type   VARCHAR(40) NOT NULL,      -- LOGIN, UPLOAD, SCAN, ENCRYPT, DECRYPT, VIEW, DOWNLOAD, DELETE
    details    VARCHAR(255) NULL,
    act_time   DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- tamper-evident chain (added at runtime by includes/audit.php; NULL on older rows)
    file_ref   INT      NULL,                -- copy of file_id at logging time (file_id may later become NULL)
    key_ref    INT      NULL,                -- copy of key_id at logging time
    chain_seq  INT      NULL,                -- 1, 2, 3 ... per user
    prev_hash  CHAR(64) NULL,                -- row_hash of the previous entry of this user
    row_hash   CHAR(64) NULL,                -- HMAC-SHA256 over the entry and prev_hash
    KEY idx_actions_chain (user_id, act_id),
    CONSTRAINT fk_act_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_act_file FOREIGN KEY (file_id)
        REFERENCES files(file_id) ON DELETE SET NULL,
    CONSTRAINT fk_act_key  FOREIGN KEY (key_id)
        REFERENCES file_keys(key_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- RATE_LIMITS table (login / OTP / register / upload throttling)
-- Created automatically by includes/ratelimit.php; keys are SHA-256 hashes.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limits (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    bucket     VARCHAR(32)  NOT NULL,
    k          CHAR(64)     NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_rl (bucket, k, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- AUDIT_HEADS table (sealed head of each user's audit chain, detects removal of the latest entries)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_heads (
    user_id INT       NOT NULL PRIMARY KEY,
    seq     INT       NOT NULL DEFAULT 0,
    head    CHAR(64)  NOT NULL,
    mac     CHAR(64)  NOT NULL,
    CONSTRAINT fk_audit_head_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Useful indexes
CREATE INDEX idx_files_user      ON files(user_id);
CREATE INDEX idx_actions_user    ON actions(user_id);
CREATE INDEX idx_actions_time    ON actions(act_time);
