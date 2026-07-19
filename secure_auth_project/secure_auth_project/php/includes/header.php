<?php
if (session_status() === PHP_SESSION_NONE) { session_start(); }
if (!isset($pageTitle)) { $pageTitle = 'Secure Auth & Threat Detection'; }
$current = basename($_SERVER['SCRIPT_NAME']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title><?= e($pageTitle) ?></title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<nav class="navbar">
    <span class="brand">🛡 SecureAuth</span>
    <a href="dashboard.php" class="<?= $current==='dashboard.php'?'active':'' ?>">Dashboard</a>
    <a href="users.php" class="<?= $current==='users.php'||$current==='user_form.php'?'active':'' ?>">Users</a>
    <a href="login_attempts.php" class="<?= $current==='login_attempts.php'?'active':'' ?>">Login Attempts</a>
    <a href="security_logs.php" class="<?= $current==='security_logs.php'?'active':'' ?>">Security Logs</a>
    <a href="blocked_ips.php" class="<?= $current==='blocked_ips.php'?'active':'' ?>">Blocked IPs</a>
    <a href="audit_records.php" class="<?= $current==='audit_records.php'?'active':'' ?>">Audit Trail</a>
    <a href="demo_procedures.php" class="<?= $current==='demo_procedures.php'?'active':'' ?>">Viva Demo</a>
    <?php if (!empty($_SESSION['username'])): ?>
        <span style="margin-left:auto; color:#94a3b8; font-size:0.9rem;">👤 <?= e($_SESSION['username']) ?></span>
        <a href="logout.php">Log Out</a>
    <?php endif; ?>
</nav>
<div class="container">
