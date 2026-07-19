<?php
// Include this at the top of any page (after config.php) that should require login.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
if (empty($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}
