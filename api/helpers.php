<?php
// ============================================================
//  helpers.php — CORS, sessions, CSRF, mailer, utilities
// ============================================================
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

// ── CORS for same-origin path-based setup ────────────────────
// Since everything is on localhost, we only need to allow localhost.
function set_cors(): void {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if (str_starts_with($origin, 'http://localhost')) {
        header("Access-Control-Allow-Origin: {$origin}");
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
    }
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204); exit;
    }
}

// ── JSON output ───────────────────────────────────────────────
function json_out(array $data, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function json_error(string $msg, int $code = 400): never {
    json_out(['success' => false, 'error' => $msg], $code);
}

// ── Read JSON request body ────────────────────────────────────
function body(): array {
    static $d = null;
    if ($d === null) {
        $raw = file_get_contents('php://input');
        $d   = json_decode($raw, true) ?? [];
    }
    return $d;
}

function start_csrf_session(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_name('vault_csrf_sess');
        session_save_path("C:\\php-project-session");
        session_set_cookie_params([
            'lifetime' => CSRF_TTL,
            'path'     => '/',
            'secure'   => false,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }
}

// ── CSRF token (stored in session, validated per request) ─────
function csrf_token(): string {
    start_csrf_session();
    if (empty($_SESSION['csrf_token']) || (time() - ($_SESSION['csrf_ts'] ?? 0)) > CSRF_TTL) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_ts']    = time();
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(): void {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['_csrf'] ?? (body()['_csrf'] ?? '');
    // Re-init session to read stored token
    start_csrf_session();
    $stored = $_SESSION['csrf_token'] ?? '';
    if (!$stored || !hash_equals($stored, $token)) {
        json_error('Invalid CSRF token. Please refresh and try again.', 403);
    }
}

// ── Session management ────────────────────────────────────────
function create_session(int $user_id): void {
    $token      = bin2hex(random_bytes(48));
    $expires_at = date('Y-m-d H:i:s', time() + SESSION_TTL);
    $ip         = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua         = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

    $pdo = get_db();
    $pdo->prepare(
        'INSERT INTO sessions (id, user_id, ip, user_agent, expires_at) VALUES (?,?,?,?,?)'
    )->execute([$token, $user_id, $ip, $ua, $expires_at]);

    setcookie(SESSION_COOKIE, $token, [
        'expires'  => time() + SESSION_TTL,
        'path'     => '/',
        'secure'   => false,     // set true when using HTTPS
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function get_athed_user(): ?array {
    $token = $_COOKIE[SESSION_COOKIE] ?? '';
    if (!$token || strlen($token) < 64) return null;

    $pdo  = get_db();
    $stmt = $pdo->prepare(
        "SELECT u.* FROM users u
         JOIN sessions s ON s.user_id = u.id
         WHERE s.id = ? AND s.expires_at > datetime('now')"
    );
    $stmt->execute([$token]);
    return $stmt->fetch() ?: null;
}

function require_auth(): array {
    $user = get_athed_user();
    if (!$user) json_error('Not authenticated', 401);
    return $user;
}

function destroy_session(): void {
    $token = $_COOKIE[SESSION_COOKIE] ?? '';
    if ($token) {
        get_db()->prepare('DELETE FROM sessions WHERE id = ?')->execute([$token]);
    }
    setcookie(SESSION_COOKIE, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => false,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

// ── OTP helpers ───────────────────────────────────────────────
function generate_otp(): string {
    // 6-digit numeric OTP
    return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function store_otp(string $email, string $plainOtp, string $purpose): void {
    $pdo       = get_db();
    $hash      = password_hash($plainOtp, PASSWORD_BCRYPT);
    $expires   = date('Y-m-d H:i:s', time() + OTP_TTL);

    // Invalidate any existing OTPs for this email+purpose
    $pdo->prepare("DELETE FROM otps WHERE email = ? AND purpose = ?")->execute([$email, $purpose]);

    $pdo->prepare(
        'INSERT INTO otps (email, code, purpose, expires_at) VALUES (?,?,?,?)'
    )->execute([$email, $hash, $purpose, $expires]);
}

function verify_otp(string $email, string $plainOtp, string $purpose): bool {
    $pdo  = get_db();
    $stmt = $pdo->prepare(
        "SELECT * FROM otps WHERE email = ? AND purpose = ? AND expires_at > datetime('now') ORDER BY id DESC LIMIT 1"
    );
    $stmt->execute([$email, $purpose]);
    $row = $stmt->fetch();

    if (!$row) return false;

    // Increment try counter
    $pdo->prepare('UPDATE otps SET tries = tries + 1 WHERE id = ?')->execute([$row['id']]);

    if ((int)$row['tries'] >= OTP_MAX_TRIES) {
        // Burn the OTP on too many tries
        $pdo->prepare('DELETE FROM otps WHERE id = ?')->execute([$row['id']]);
        return false;
    }

    if (!password_verify($plainOtp, $row['code'])) return false;

    // OTP used — delete it
    $pdo->prepare('DELETE FROM otps WHERE id = ?')->execute([$row['id']]);
    return true;
}

function check_otp_rate_limit(string $email): bool {
    $pdo  = get_db();
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM otps WHERE email = ? AND created_at > datetime('now', '-1 hour')"
    );
    $stmt->execute([$email]);
    return (int)$stmt->fetchColumn() < OTP_RATE_LIMIT;
}

// ── Simple SMTP mailer (no dependencies) ─────────────────────
function send_otp_email(string $toEmail, string $otp, string $purpose): bool {
    $subject = match($purpose) {
        'register' => 'Verify your Vault account',
        'reset'    => 'Reset your Vault password',
        default    => 'Your Vault login code',
    };

    $html = "
    <div style='font-family:Georgia,serif;max-width:480px;margin:0 auto;background:#0f0e0d;color:#f7f5f0;padding:40px;border-radius:12px;'>
      <h2 style='font-size:1.8rem;margin:0 0 8px;'>Vault<span style='color:#c8523a'>.</span></h2>
      <hr style='border:none;border-top:1px solid #2a2825;margin:20px 0;'>
      <p style='font-size:1rem;margin:0 0 24px;color:#b0aa9f;'>Your one-time verification code:</p>
      <div style='font-size:3rem;font-weight:700;letter-spacing:0.3em;color:#f7f5f0;background:#1a1916;border-radius:8px;padding:20px;text-align:center;'>{$otp}</div>
      <p style='margin:24px 0 0;font-size:0.85rem;color:#6a6460;'>This code expires in 5 minutes. Do not share it with anyone.</p>
    </div>
    ";

    // Use PHP's mail() for simple local sending, or SMTP if configured
    if (SMTP_USER !== 'YOUR_MAILTRAP_USER') {
        return smtp_send($toEmail, $subject, $html);
    }

    // Fallback: PHP mail() — works if a local MTA is configured
    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: " . SMTP_FROM_NAME . " <" . SMTP_FROM . ">\r\n";
    return mail($toEmail, $subject, $html, $headers);
}

function smtp_send(string $to, string $subject, string $html): bool {
    try {
        $sock = fsockopen(SMTP_HOST, SMTP_PORT, $errno, $errstr, 10);
        if (!$sock) return false;

        $read = fn() => fgets($sock, 512);
        $send = function(string $cmd) use ($sock, $read) {
            fwrite($sock, $cmd . "\r\n");
            return $read();
        };

        $read(); // 220 greeting
        $send('EHLO localhost');
        // Read multi-line EHLO response
        while (($line = $read()) && str_starts_with($line, '250-')) {}

        $send('AUTH LOGIN');
        $send(base64_encode(SMTP_USER));
        $send(base64_encode(SMTP_PASS));
        $send('MAIL FROM:<' . SMTP_FROM . '>');
        $send('RCPT TO:<' . $to . '>');
        $send('DATA');

        $msg  = "From: " . SMTP_FROM_NAME . " <" . SMTP_FROM . ">\r\n";
        $msg .= "To: {$to}\r\n";
        $msg .= "Subject: {$subject}\r\n";
        $msg .= "MIME-Version: 1.0\r\n";
        $msg .= "Content-Type: text/html; charset=UTF-8\r\n";
        $msg .= "\r\n" . $html . "\r\n.\r\n";
        fwrite($sock, $msg);
        $read(); // 250 OK

        $send('QUIT');
        fclose($sock);
        return true;
    } catch (\Throwable $e) {
        error_log('SMTP error: ' . $e->getMessage());
        return false;
    }
}

// ── File upload helper ────────────────────────────────────────
function handle_avatar_upload(int $user_id): ?string {
    if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
        return null;
    }

    $file = $_FILES['avatar'];

    // Size check
    if ($file['size'] > MAX_UPLOAD_BYTES) {
        json_error('Image must be under 2 MB');
    }

    // MIME type check using finfo (don't trust the browser's mime type)
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($file['tmp_name']);
    if (!in_array($mime, ALLOWED_MIME, true)) {
        json_error('Only JPEG, PNG, GIF and WebP images are allowed');
    }

    // Generate a unique filename — never use the user-supplied filename
    $ext      = match($mime) {
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
        default      => 'jpg',
    };
    $filename = 'avatar_' . $user_id . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
    $dest     = UPLOAD_DIR . $filename;

    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0750, true);

    if (!move_uploaded_file($file['tmp_name'], $dest)) {
        json_error('Upload failed — could not save file');
    }

    return $filename;
}

// ── Input sanitizer ───────────────────────────────────────────
function clean(string $val, int $maxLen = 255): string {
    return substr(trim(strip_tags($val)), 0, $maxLen);
}
