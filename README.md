# Vault — OTP Authentication & User Directory

A secure user authentication and profile management web app running locally on Windows with Nginx + PHP + SQLite. No cloud server or domain required.

---

## Features

- **OTP login** — 6-digit code sent to email, no password required
- **Password login** — optional fallback with forgot password flow
- **Profile page** — upload avatar, edit personal details (name, bio, job title, location, github, website)
- **Member directory** — searchable list of all registered users with avatars
- **Session management** — secure httpOnly cookies, 30-day sessions
- **Rate limiting** — OTP endpoint limited to 10 requests/minute per IP

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, Vanilla JavaScript |
| Backend | PHP 8.5 |
| Database | SQLite (single file, no server needed) |
| Web Server | Nginx 1.28 |
| Email | SMTP via Mailtrap (for local testing) |

---

## Security Practices

- **OTPs hashed with bcrypt** — raw codes never stored in database
- **Passwords hashed with Argon2id** — strongest standard algorithm
- **CSRF protection** — every state-changing request requires a token
- **httpOnly + SameSite cookies** — JavaScript cannot access session tokens
- **File upload validation** — MIME type checked via `finfo`, not just extension
- **Random filenames on upload** — user-supplied filenames never used
- **PHP execution blocked in uploads folder** — nginx denies all scripts there
- **SQLite database outside web root** — cannot be downloaded via browser
- **Timing-safe password comparison** — prevents timing attacks on login
- **OTP rate limiting** — max 5 OTPs per email per hour
- **OTP try limiting** — burns after 5 wrong attempts
- **CORS protection** — only requests from localhost are accepted by the API
- **SQL injection prevention** — all database queries use PDO prepared statements

---

## Project Structure

```
otp-website/
├── auth/
│   └── index.html        ← Login / register / OTP page
├── app/
│   └── profile.html      ← Profile + directory page
└── api/
    ├── config.php         ← All settings (do not commit secrets)
    ├── db.php             ← SQLite schema
    ├── helpers.php        ← Session, OTP, CSRF, email, upload
    └── index.php          ← API router

C:\php-project-session\   ← Outside web root (not served by nginx)
├── vault.db              ← SQLite database
├── uploads\              ← Profile pictures
└── sessions\             ← PHP session files
```

---

## Setup

### Requirements

- Windows 10/11
- [Nginx for Windows](http://nginx.org/en/download.html) — extract to `C:\nginx`
- [PHP 8.x NTS](https://windows.php.net/download/) — extract to your preferred folder
- [Mailtrap](https://mailtrap.io) free account — for receiving OTP emails during testing

### Steps

**1. Create required folders**
```powershell
New-Item -ItemType Directory -Force -Path "C:\php-project-session\uploads"
New-Item -ItemType Directory -Force -Path "C:\php-project-session\sessions"
```

**2. Configure PHP**

In `php.ini` uncomment:
```ini
extension_dir = "C:\path\to\php\ext"
extension=pdo_sqlite
extension=sqlite3
extension=fileinfo
extension=curl
extension=mbstring
extension=openssl
```

**3. Edit `api/config.php`**

```php
define('SESSION_SECRET', 'your-random-64-char-string');
define('SMTP_USER',      'your-mailtrap-username');
define('SMTP_PASS',      'your-mailtrap-password');
define('DB_PATH',        'C:\\php-project-session\\vault.db');
define('UPLOAD_DIR',     'C:\\php-project-session\\uploads\\');
```

**4. Update `nginx.conf`** with your actual paths and copy it to `C:\nginx\conf\nginx.conf`

**5. Initialize the database**
```powershell
cd path\to\otp-website\api
php.exe -r "require 'db.php'; get_db(); echo 'OK';"
```

**6. Start PHP and Nginx**

PowerShell window 1:
```powershell
C:\path\to\php\php-cgi.exe -c "C:\path\to\php\php.ini" -b 127.0.0.1:9000
```

PowerShell window 2:
```powershell
cd C:\nginx
.\nginx.exe
```

**7. Open browser**
```
http://localhost
```

---

## Important

- Never commit `config.php` — add it to `.gitignore`
- `config.php` contains your SMTP credentials and session secret
- The `.gitignore` below is recommended

```gitignore
api/config.php
*.db
*.log
uploads/
sessions/
```
