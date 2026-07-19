<?php
require 'config.php';
require 'includes/auth.php';
$pageTitle = 'Viva Demo';
$result = null;
$action = $_POST['action'] ?? '';

try {
    if ($action === 'call_login_proc') {
        $stmt = $pdo->prepare("CALL sp_process_login_attempt(?, ?, ?, ?)");
        $stmt->execute([
            $_POST['username'], $_POST['ip'],
            isset($_POST['success']) ? 't' : 'f',
            'Viva demo call',
        ]);
        $result = "sp_process_login_attempt('{$_POST['username']}', '{$_POST['ip']}', "
                 . (isset($_POST['success']) ? 'TRUE' : 'FALSE') . ") executed. Check Login Attempts / Blocked IPs / Security Logs.";
    }

    if ($action === 'call_deactivate_proc') {
        $stmt = $pdo->prepare("CALL sp_deactivate_user(?, ?, ?)");
        $stmt->execute([$_POST['user_id'], 1, $_POST['reason']]);
        $result = "sp_deactivate_user({$_POST['user_id']}, 1, '{$_POST['reason']}') executed. Check Audit Trail and Users.";
    }

    if ($action === 'call_fn_failed') {
        $stmt = $pdo->prepare("SELECT fn_get_failed_attempts(?, ?) AS result");
        $stmt->execute([$_POST['ip'], $_POST['minutes']]);
        $result = "fn_get_failed_attempts('{$_POST['ip']}', {$_POST['minutes']}) = " . $stmt->fetch()['result'];
    }

    if ($action === 'call_fn_blocked') {
        $stmt = $pdo->prepare("SELECT fn_is_ip_blocked(?) AS result");
        $stmt->execute([$_POST['ip']]);
        $result = "fn_is_ip_blocked('{$_POST['ip']}') = " . ($stmt->fetch()['result'] ? 'TRUE (blocked)' : 'FALSE (not blocked)');
    }
} catch (PDOException $e) {
    $result = 'ERROR: ' . $e->getMessage();
}

require 'includes/header.php';
?>
<h1>Viva Demo Console</h1>
<p class="subtitle">Direct, isolated calls to each procedure/function for the demo - so you can show the examiner exactly what each one does without digging through other pages.</p>

<?php if ($result): ?><div class="alert alert-info"><?= e($result) ?></div><?php endif; ?>

<div class="panel">
    <h2 style="margin-top:0">1. CALL sp_process_login_attempt(username, ip, success, user_agent)</h2>
    <p style="color:#94a3b8">Logs the attempt, updates the user, and auto-blocks the IP + writes a CRITICAL security log if 5+ failed attempts happen from that IP within 15 minutes.</p>
    <form method="post" class="filters">
        <input type="text" name="username" placeholder="username (e.g. user1)" required>
        <input type="text" name="ip" placeholder="IP address" required>
        <label style="display:flex;align-items:center;gap:0.4rem"><input type="checkbox" name="success"> Success</label>
        <button class="btn" type="submit" name="action" value="call_login_proc">Run Procedure</button>
    </form>
</div>

<div class="panel">
    <h2 style="margin-top:0">2. CALL sp_deactivate_user(user_id, admin_id, reason)</h2>
    <p style="color:#94a3b8">Deactivates the user and writes a matching audit_records row in the same transaction.</p>
    <form method="post" class="filters">
        <input type="number" name="user_id" placeholder="user_id (e.g. 50)" required>
        <input type="text" name="reason" placeholder="Reason" required style="min-width:220px">
        <button class="btn" type="submit" name="action" value="call_deactivate_proc">Run Procedure</button>
    </form>
</div>

<div class="panel">
    <h2 style="margin-top:0">3. SELECT fn_get_failed_attempts(ip, minutes)</h2>
    <form method="post" class="filters">
        <input type="text" name="ip" placeholder="IP address" required>
        <input type="number" name="minutes" value="15" required style="width:120px">
        <button class="btn" type="submit" name="action" value="call_fn_failed">Run Function</button>
    </form>
</div>

<div class="panel">
    <h2 style="margin-top:0">4. SELECT fn_is_ip_blocked(ip)</h2>
    <form method="post" class="filters">
        <input type="text" name="ip" placeholder="IP address" required>
        <button class="btn" type="submit" name="action" value="call_fn_blocked">Run Function</button>
    </form>
</div>

<div class="panel">
    <h2 style="margin-top:0">Tip for the viva</h2>
    <p style="color:#94a3b8">
        To show <code>trg_flag_failed_login</code> firing live: go to <a href="login_attempts.php">Login Attempts</a> and
        record 5 failed attempts in a row using the <strong>same IP address</strong> without ticking "Success" - then open
        <a href="security_logs.php">Security Logs</a> and point out the new BRUTE_FORCE entry that appeared automatically.
        To show <code>trg_audit_user_update</code>: edit any user on the <a href="users.php">Users</a> page (e.g. flip Active off),
        then open <a href="audit_records.php">Audit Trail</a> and show the new row that was written without calling any procedure.
    </p>
</div>

<?php require 'includes/footer.php'; ?>
