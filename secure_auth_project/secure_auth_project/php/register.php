<?php
require 'config.php';
$pageTitle = 'Sign Up';
$error = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username  = trim($_POST['username'] ?? '');
    $email     = trim($_POST['email'] ?? '');
    $fullName  = trim($_POST['full_name'] ?? '');
    $password  = $_POST['password'] ?? '';
    $confirm   = $_POST['confirm_password'] ?? '';

    if ($username === '' || $email === '' || $fullName === '' || $password === '') {
        $error = 'All fields are required.';
    } elseif ($password !== $confirm) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } else {
        // Check username/email isn't already taken
        $stmt = $pdo->prepare("SELECT 1 FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        if ($stmt->fetch()) {
            $error = 'That username or email is already registered.';
        } else {
            try {
                // role_id 4 = StandardUser (see roles table). New accounts self-register
                // as standard users; promoting to Admin/Analyst/Auditor is an admin action.
                $stmt = $pdo->prepare("
                    INSERT INTO users (username, email, full_name, role_id, is_active, password_hash)
                    VALUES (?, ?, ?, 4, TRUE, ?)");
                $stmt->execute([$username, $email, $fullName, md5($password)]);

                header("Location: index.php?registered=1");
                exit;
            } catch (PDOException $e) {
                $error = 'Could not create account: ' . $e->getMessage();
            }
        }
    }
}

require 'includes/header.php';
?>
<div class="panel" style="max-width:440px; margin: 2.5rem auto;">
    <h1 style="margin-top:0">Create Account</h1>
    <p class="subtitle">Passwords are hashed with MD5 here purely as a coursework placeholder for a real bcrypt/Argon2 hash.</p>

    <?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>

    <form method="post">
        <div class="field">
            <label>Full Name</label>
            <input type="text" name="full_name" value="<?= e($_POST['full_name'] ?? '') ?>" required style="width:100%">
        </div>
        <div class="field">
            <label>Username</label>
            <input type="text" name="username" value="<?= e($_POST['username'] ?? '') ?>" required style="width:100%">
        </div>
        <div class="field">
            <label>Email</label>
            <input type="email" name="email" value="<?= e($_POST['email'] ?? '') ?>" required style="width:100%">
        </div>
        <div class="field">
            <label>Password</label>
            <input type="password" name="password" required style="width:100%">
        </div>
        <div class="field">
            <label>Confirm Password</label>
            <input type="password" name="confirm_password" required style="width:100%">
        </div>
        <button class="btn" type="submit" style="width:100%">Sign Up</button>
    </form>
    <p style="margin-top:1rem; color:#94a3b8; font-size:0.9rem;">
        Already have an account? <a href="index.php">Log in</a>
    </p>
</div>
<?php require 'includes/footer.php'; ?>
