<?php
require 'config.php';
session_start();

// Already logged in? Skip the login form and go straight to the dashboard.
if (!empty($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}

$pageTitle = 'Log In';
$error = '';
$registered = isset($_GET['registered']);

$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // 1. Refuse outright if this IP is currently blocked
    $stmt = $pdo->prepare("
        SELECT 1 FROM blocked_ips
        WHERE ip_address = ? AND is_active = TRUE
          AND (blocked_until IS NULL OR blocked_until > NOW())");
    $stmt->execute([$ip]);
    if ($stmt->fetch()) {
        header("Location: login_failed.php?reason=blocked");
        exit;
    } elseif ($username === '' || $password === '') {
        $error = 'Username and password are required.';
    } else {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        $isSuccess = $user && $user['is_active'] && $user['password_hash'] === md5($password);

        // 2. Log every attempt - this is what trg_flag_failed_login watches
        $stmt = $pdo->prepare("
            INSERT INTO login_attempts (user_id, username_tried, ip_address, is_success, user_agent)
            VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$user['user_id'] ?? null, $username, $ip, $isSuccess, $userAgent]);

        if ($isSuccess) {
            $_SESSION['user_id']  = $user['user_id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role_id']  = $user['role_id'];

            $pdo->prepare("UPDATE users SET last_login = NOW(), failed_login_count = 0 WHERE user_id = ?")
                ->execute([$user['user_id']]);

            header("Location: dashboard.php");
            exit;
        } else {
            if ($user) {
                $pdo->prepare("UPDATE users SET failed_login_count = failed_login_count + 1 WHERE user_id = ?")
                    ->execute([$user['user_id']]);
            }
            header("Location: login_failed.php?u=" . urlencode($username));
            exit;
        }
    }
}

require 'includes/header.php';
?>
<div class="panel" style="max-width:400px; margin: 2.5rem auto;">
    <h1 style="margin-top:0">Log In</h1>
    <p class="subtitle">Sign in to the Security Dashboard.</p>

    <?php if ($registered): ?><div class="alert alert-success">Account created — you can log in now.</div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>

    <form method="post">
        <div class="field">
            <label>Username</label>
            <input type="text" name="username" value="<?= e($_POST['username'] ?? $_GET['username'] ?? '') ?>" required style="width:100%" autofocus>
        </div>
        <div class="field">
            <label>Password</label>
            <input type="password" name="password" required style="width:100%">
        </div>
        <button class="btn" type="submit" style="width:100%">Log In</button>
    </form>
    <p style="margin-top:1rem; color:#94a3b8; font-size:0.9rem;">
        No account? <a href="register.php">Sign up</a>
    </p>
</div>
<?php require 'includes/footer.php'; ?>
