<?php
require 'config.php';
session_start();
$pageTitle = 'Login Failed';

$reason = $_GET['reason'] ?? 'invalid';
$triedUsername = $_GET['u'] ?? '';

$message = ($reason === 'blocked')
    ? 'This IP address is currently blocked due to suspicious activity. Try again later.'
    : 'Wrong username or password.';

require 'includes/header.php';
?>
<div class="panel" style="max-width:440px; margin: 2.5rem auto; text-align:center;">
    <h1 style="margin-top:0">Login Failed</h1>
    <div class="alert alert-error"><?= e($message) ?></div>

    <?php if ($reason !== 'blocked'): ?>
        <p class="subtitle">
            Double-check your username and password, or create a new account if you don't have one yet.
        </p>
        <a href="index.php<?= $triedUsername !== '' ? '?username=' . urlencode($triedUsername) : '' ?>" class="btn" style="width:100%; display:block; margin-bottom:0.75rem;">Try Again</a>
        <a href="register.php" class="btn secondary" style="width:100%; display:block;">Create New Account</a>
    <?php else: ?>
        <a href="index.php" class="btn" style="width:100%; display:block;">Back to Login</a>
    <?php endif; ?>
</div>
<?php require 'includes/footer.php'; ?>
