<?php
// ============================================================
//  db.php — SQLite connection + schema bootstrap
// ============================================================
require_once __DIR__ . '/config.php';

function get_db(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    // Create the data directory if it doesn't exist
    $dir = dirname(DB_PATH);
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }

    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Enable WAL mode for better concurrent read performance
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA foreign_keys=ON');

    // ── Create tables if they don't exist ────────────────────
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT    DEFAULT NULL,
            name          TEXT    DEFAULT NULL,
            picture       TEXT    DEFAULT NULL,    -- filename inside UPLOAD_DIR
            provider      TEXT    NOT NULL DEFAULT 'email', -- 'email' or 'google'
            google_sub    TEXT    DEFAULT NULL UNIQUE,
            email_verified INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            first_name TEXT DEFAULT NULL,
            last_name  TEXT DEFAULT NULL,
            job_title  TEXT DEFAULT NULL,
            location   TEXT DEFAULT NULL,
            website    TEXT DEFAULT NULL,
            github     TEXT DEFAULT NULL,
            bio        TEXT DEFAULT NULL,
            phone      TEXT DEFAULT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS sessions (
            id         TEXT    PRIMARY KEY,          -- random 96-hex token
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ip         TEXT    DEFAULT NULL,
            user_agent TEXT    DEFAULT NULL,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT    NOT NULL
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS otps (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT    NOT NULL COLLATE NOCASE,
            code       TEXT    NOT NULL,             -- hashed OTP
            purpose    TEXT    NOT NULL DEFAULT 'login',  -- 'login' | 'register' | 'reset'
            tries      INTEGER NOT NULL DEFAULT 0,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT    NOT NULL
        )
    ");

    // Index on email for fast OTP lookups
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_otps_email ON otps(email)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)");

    return $pdo;
}
