<?php
ini_set('error_log', 'C:/Users/deepa/OneDrive/Documents/otp-website/data/php_errors.log');
// ============================================================
//  index.php — API router  (localhost/api/*)
// ============================================================
require_once __DIR__ . '/helpers.php';

set_cors();
header('Content-Type: application/json');

$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
// Strip the /api prefix if present
$path   = preg_replace('#^/api#', '', $uri) ?: '/';
$path   = rtrim($path, '/') ?: '/';
$method = $_SERVER['REQUEST_METHOD'];

// ─────────────────────────────────────────────────────────────
//  AUTH routes (no session required)
// ─────────────────────────────────────────────────────────────

// ── GET /csrf — fetch a CSRF token ──────────────────────────
if ($method === 'GET' && $path === '/csrf') {
    json_out(['token' => csrf_token()]);
}

// ── POST /auth/send-otp ──────────────────────────────────────
// Send OTP to email. Works for login, register, and password reset.
if ($method === 'POST' && $path === '/auth/send-otp') {
    verify_csrf();
    $b       = body();
    $email   = filter_var(trim($b['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $purpose = in_array($b['purpose'] ?? '', ['login','register','reset'], true)
                 ? $b['purpose'] : 'login';

    if (!$email) json_error('Please enter a valid email address.');

    // Rate limit check
    if (!check_otp_rate_limit($email)) {
        json_error('Too many OTP requests. Please wait an hour before trying again.', 429);
    }

    $pdo  = get_db();
    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    // For login: user must exist
    if ($purpose === 'login' && !$user) {
        json_error('No account found with that email. Please register first.');
    }
    // For register: email must not be taken
    if ($purpose === 'register' && $user) {
        json_error('An account with this email already exists. Please login.');
    }

    $otp = generate_otp();
    store_otp($email, $otp, $purpose);

    $sent = send_otp_email($email, $otp, $purpose);
    if (!$sent) {
        // For local dev, return OTP in response (REMOVE IN PRODUCTION)
        json_out([
            'success' => true,
            'dev_otp' => $otp,
            'message' => 'Email send failed (check SMTP config). Dev OTP shown below — remove in production.',
        ]);
    }

    json_out(['success' => true, 'message' => "OTP sent to {$email}. Check your inbox."]);
}

// ── POST /auth/verify-otp — verify OTP and log in ───────────
if ($method === 'POST' && $path === '/auth/verify-otp') {
    verify_csrf();
    $b       = body();
    $email   = filter_var(trim($b['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $otp     = preg_replace('/\D/', '', $b['otp'] ?? '');
    $purpose = in_array($b['purpose'] ?? '', ['login','register','reset'], true)
                 ? $b['purpose'] : 'login';

    if (!$email || strlen($otp) !== 6) json_error('Invalid email or OTP format.');

    if (!verify_otp($email, $otp, $purpose)) {
        json_error('Incorrect or expired OTP. Please try again.');
    }

    $pdo  = get_db();
    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($purpose === 'register') {
        // Create the user
        $pdo->prepare(
            'INSERT INTO users (email, email_verified, provider) VALUES (?, 1, ?)'
        )->execute([$email, 'email']);

        $user_id = (int)$pdo->lastInsertId();

        // Create empty profile row
        $pdo->prepare('INSERT INTO user_profiles (user_id) VALUES (?)')->execute([$user_id]);

        create_session($user_id);
        json_out(['success' => true, 'redirect' => '/app/profile.html']);
    }

    if ($purpose === 'login') {
        if (!$user) json_error('Account not found.');
        // Mark email as verified on first login via OTP
        $pdo->prepare('UPDATE users SET email_verified = 1 WHERE id = ?')->execute([$user['id']]);
        create_session((int)$user['id']);
        json_out(['success' => true, 'redirect' => '/app/profile.html']);
    }

    // Purpose = reset — return a short-lived reset token
    if ($purpose === 'reset') {
        if (!$user) json_error('Account not found.');
        $reset_token = bin2hex(random_bytes(24));
        // Store temporarily in session
        if (session_status() === PHP_SESSION_NONE) { session_name('vault_csrf_sess'); session_start(); }
        $_SESSION['reset_token'] = $reset_token;
        $_SESSION['reset_email'] = $email;
        $_SESSION['reset_ts']    = time();
        json_out(['success' => true, 'reset_token' => $reset_token]);
    }
}

// ── POST /auth/set-password — set password after OTP reset ──
if ($method === 'POST' && $path === '/auth/set-password') {
    verify_csrf();
    if (session_status() === PHP_SESSION_NONE) { session_name('vault_csrf_sess'); session_start(); }

    $b     = body();
    $token = $b['reset_token'] ?? '';
    $pass  = $b['password']    ?? '';

    $stored = $_SESSION['reset_token'] ?? '';
    $email  = $_SESSION['reset_email'] ?? '';
    $ts     = $_SESSION['reset_ts']    ?? 0;

    if (!$stored || !hash_equals($stored, $token) || (time() - $ts) > 600) {
        json_error('Password reset session expired. Please start over.');
    }

    if (strlen($pass) < 8) json_error('Password must be at least 8 characters.');

    $hash = password_hash($pass, PASSWORD_ARGON2ID);
    get_db()->prepare('UPDATE users SET password_hash = ? WHERE email = ?')->execute([$hash, $email]);

    unset($_SESSION['reset_token'], $_SESSION['reset_email'], $_SESSION['reset_ts']);
    json_out(['success' => true]);
}

// ── POST /auth/login-password — traditional password login ──
if ($method === 'POST' && $path === '/auth/login-password') {
    verify_csrf();
    $b     = body();
    $email = filter_var(trim($b['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $pass  = $b['password'] ?? '';

    if (!$email || !$pass) json_error('Email and password required.');

    $pdo  = get_db();
    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    // Constant-time dummy hash to prevent timing attacks
    $hash = $user['password_hash']
          ?? '$argon2id$v=19$m=65536,t=4,p=1$ZHVtbXlkdW1teWR1bW15$ZHVtbXlkdW1teWR1bW15ZHVtbXlkdW1teWR1bW15';

    if (!$user || !password_verify($pass, $hash)) {
        json_error('Invalid email or password.');
    }

    create_session((int)$user['id']);
    json_out(['success' => true, 'redirect' => '/app/profile.html']);
}

// ── POST /auth/logout ─────────────────────────────────────────
if ($method === 'POST' && $path === '/auth/logout') {
    destroy_session();
    json_out(['success' => true, 'redirect' => '/auth/']);
}

// ─────────────────────────────────────────────────────────────
//  PROTECTED routes (session required)
// ─────────────────────────────────────────────────────────────

// ── GET /me ───────────────────────────────────────────────────
if ($method === 'GET' && $path === '/me') {
    $user = require_auth();
    json_out([
        'user' => [
            'id'       => $user['id'],
            'email'    => $user['email'],
            'name'     => $user['name'],
            'picture'  => $user['picture'] ? UPLOAD_URL . $user['picture'] : null,
            'provider' => $user['provider'],
        ]
    ]);
}

// ── GET /profile ──────────────────────────────────────────────
if ($method === 'GET' && $path === '/profile') {
    $user = require_auth();
    $pdo  = get_db();

    $stmt = $pdo->prepare('SELECT * FROM user_profiles WHERE user_id = ?');
    $stmt->execute([$user['id']]);
    $profile = $stmt->fetch() ?: [];

    json_out([
        'user' => [
            'id'       => $user['id'],
            'email'    => $user['email'],
            'name'     => $user['name'],
            'picture'  => $user['picture'] ? UPLOAD_URL . $user['picture'] : null,
            'provider' => $user['provider'],
        ],
        'profile' => $profile,
    ]);
}

// ── POST /profile — save profile info + optional avatar ──────
// Accepts multipart/form-data (because of file upload)
if ($method === 'POST' && $path === '/profile') {
    $user = require_auth();

    // CSRF check from form field (not header, because multipart)
    verify_csrf(); 
    $pdo = get_db();

    // ── Handle avatar upload ──────────────────────────────────
    $new_filename = null;
    if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
        $new_filename = handle_avatar_upload((int)$user['id']);

        // Delete old avatar file if it exists
        if ($user['picture'] && file_exists(UPLOAD_DIR . $user['picture'])) {
            @unlink(UPLOAD_DIR . $user['picture']);
        }

        $pdo->prepare('UPDATE users SET picture = ?, updated_at = datetime(\'now\') WHERE id = ?')
            ->execute([$new_filename, $user['id']]);
    }

    // ── Save profile fields ───────────────────────────────────
    $fields = ['first_name','last_name','job_title','location','website','github','bio','phone'];
    $vals   = [];
    foreach ($fields as $f) {
        $vals[$f] = isset($_POST[$f]) ? clean($_POST[$f]) : null;
    }

    // Name shortcut: update users.name too
    $display = trim(($vals['first_name'] ?? '') . ' ' . ($vals['last_name'] ?? ''));
    if ($display) {
        $pdo->prepare("UPDATE users SET name = ?, updated_at = datetime('now') WHERE id = ?")
            ->execute([$display, $user['id']]);
    }

    // Upsert profile row
    $pdo->prepare("
        INSERT INTO user_profiles (user_id, first_name, last_name, job_title, location, website, github, bio, phone, updated_at)
        VALUES (:uid, :fn, :ln, :jt, :loc, :web, :gh, :bio, :ph, datetime('now'))
        ON CONFLICT(user_id) DO UPDATE SET
            first_name = excluded.first_name,
            last_name  = excluded.last_name,
            job_title  = excluded.job_title,
            location   = excluded.location,
            website    = excluded.website,
            github     = excluded.github,
            bio        = excluded.bio,
            phone      = excluded.phone,
            updated_at = datetime('now')
    ")->execute([
        ':uid' => $user['id'],
        ':fn'  => $vals['first_name'],
        ':ln'  => $vals['last_name'],
        ':jt'  => $vals['job_title'],
        ':loc' => $vals['location'],
        ':web' => $vals['website'],
        ':gh'  => $vals['github'],
        ':bio' => $vals['bio'],
        ':ph'  => $vals['phone'],
    ]);

    json_out([
        'success' => true,
        'picture' => $new_filename ? UPLOAD_URL . $new_filename : null,
    ]);
}

// ── GET /users — directory ────────────────────────────────────
if ($method === 'GET' && $path === '/users') {
    require_auth();
    $pdo  = get_db();
    $rows = $pdo->query("
        SELECT u.id, u.name, u.email,
               CASE WHEN u.picture IS NOT NULL THEN ('" . UPLOAD_URL . "' || u.picture) ELSE NULL END AS picture,
               p.first_name, p.last_name, p.job_title, p.location, p.bio
        FROM users u
        LEFT JOIN user_profiles p ON p.user_id = u.id
        ORDER BY u.created_at DESC
        LIMIT 200
    ")->fetchAll();

    json_out(['users' => $rows]);
}

// ── 404 ───────────────────────────────────────────────────────
json_error("Route not found: {$path}", 404);
