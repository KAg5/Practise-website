<?php
// ============================================================
//  config.php
//  Edit the values in this file before running the app.
// ============================================================

// ── Paths ────────────────────────────────────────────────────
// Absolute path to the SQLite database file.
// Keep it OUTSIDE the web root so it cannot be downloaded.
// On Windows with this project at C:\vault\ → 'C:/vault/data/vault.db'
define('DB_PATH','C:\\php-project-session\\vault.db');

// Where uploaded profile pictures are stored (inside web root so they're servable).
// This maps to localhost/uploads/
define('UPLOAD_DIR','C:\\php-project-session\\uploads\\');
define('UPLOAD_URL',   '/uploads/');     // URL prefix to reach uploaded files

// ── Session ──────────────────────────────────────────────────
// Change this to any long random string. Used to sign session tokens.
// Generate one: open PowerShell → [System.Web.Security.Membership]::GeneratePassword(64,10)
define('SESSION_SECRET', '00166a3af6a1fc7b5f74b5d4c929e83b49bc029a1680ee2c6499bf3f33dd135e');

// Session cookie name
define('SESSION_COOKIE', 'vault_sid');

// Session lifetime in seconds (30 days)
define('SESSION_TTL', 60 * 60 * 24 * 30);

// ── OTP ──────────────────────────────────────────────────────
// How many seconds an OTP is valid
define('OTP_TTL',        300);   // 5 minutes

// How many OTP attempts are allowed before lockout
define('OTP_MAX_TRIES',  5);

// Max OTP sends per email per hour (rate limiting)
define('OTP_RATE_LIMIT', 5);

// ── Email (SMTP) ─────────────────────────────────────────────
// For local testing you can use Mailtrap (https://mailtrap.io) — free fake inbox.
// Sign up → Inboxes → SMTP credentials → fill these in.
define('SMTP_HOST',     'sandbox.smtp.mailtrap.io');
define('SMTP_PORT',     2525);
define('SMTP_USER',     'YOUR_MAILTRAP_USER');
define('SMTP_PASS',     'YOUR_MAILTRAP_PASS');
define('SMTP_FROM',     'no-reply@vault.local');
define('SMTP_FROM_NAME','Vault');

// ── Security ──────────────────────────────────────────────────
// Allowed image MIME types for profile picture uploads
define('ALLOWED_MIME', ['image/jpeg', 'image/png', 'image/gif', 'image/webp']);

// Max upload size in bytes (2 MB)
define('MAX_UPLOAD_BYTES', 2 * 1024 * 1024);

// CSRF token lifetime in seconds
define('CSRF_TTL', 3600);

// ── App URL ───────────────────────────────────────────────────
define('APP_BASE', 'http://localhost');
