<?php
require 'config.php';
require 'includes/auth.php';
$pageTitle = 'Dashboard';

$stats = [];
$stats['users']        = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn();
$stats['active_users'] = $pdo->query("SELECT COUNT(*) FROM users WHERE is_active = TRUE")->fetchColumn();
$stats['attempts']     = $pdo->query("SELECT COUNT(*) FROM login_attempts")->fetchColumn();
$stats['failed_24h']   = $pdo->query("SELECT COUNT(*) FROM login_attempts WHERE is_success = FALSE AND attempt_time >= NOW() - INTERVAL '24 hours'")->fetchColumn();
$stats['blocked']      = $pdo->query("SELECT COUNT(*) FROM blocked_ips WHERE is_active = TRUE")->fetchColumn();
$stats['critical_logs']= $pdo->query("SELECT COUNT(*) FROM security_logs WHERE severity = 'CRITICAL'")->fetchColumn();
$stats['open_alerts']  = $pdo->query("SELECT COUNT(*) FROM threat_alerts WHERE resolved = FALSE")->fetchColumn();
$stats['audit']        = $pdo->query("SELECT COUNT(*) FROM audit_records")->fetchColumn();

$recentLogs = $pdo->query("
    SELECT log_id, event_type, severity, ip_address, description, created_at
    FROM security_logs ORDER BY created_at DESC LIMIT 8
")->fetchAll();

$recentAlerts = $pdo->query("
    SELECT alert_id, ip_address, threat_type, detected_at, resolved
    FROM threat_alerts ORDER BY detected_at DESC LIMIT 8
")->fetchAll();

require 'includes/header.php';
?>
<h1>Security Dashboard</h1>
<p class="subtitle">Live overview of authentication activity and detected threats.</p>

<div class="cards">
    <div class="card"><div class="num"><?= $stats['users'] ?></div><div class="label">Total Users</div></div>
    <div class="card ok"><div class="num"><?= $stats['active_users'] ?></div><div class="label">Active Users</div></div>
    <div class="card"><div class="num"><?= $stats['attempts'] ?></div><div class="label">Total Login Attempts</div></div>
    <div class="card warn"><div class="num"><?= $stats['failed_24h'] ?></div><div class="label">Failed Logins (24h)</div></div>
    <div class="card danger"><div class="num"><?= $stats['blocked'] ?></div><div class="label">Currently Blocked IPs</div></div>
    <div class="card danger"><div class="num"><?= $stats['critical_logs'] ?></div><div class="label">Critical Security Logs</div></div>
    <div class="card warn"><div class="num"><?= $stats['open_alerts'] ?></div><div class="label">Unresolved Threat Alerts</div></div>
    <div class="card"><div class="num"><?= $stats['audit'] ?></div><div class="label">Audit Records</div></div>
</div>

<div class="panel">
    <h2 style="margin-top:0">Recent Security Log Events</h2>
    <table>
        <tr><th>ID</th><th>Event Type</th><th>Severity</th><th>IP Address</th><th>Description</th><th>Time</th></tr>
        <?php foreach ($recentLogs as $log): ?>
        <tr>
            <td>#<?= $log['log_id'] ?></td>
            <td><?= e($log['event_type']) ?></td>
            <td><span class="badge badge-<?= e($log['severity']) ?>"><?= e($log['severity']) ?></span></td>
            <td><?= e($log['ip_address']) ?></td>
            <td><?= e($log['description']) ?></td>
            <td><?= e($log['created_at']) ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <p style="margin-top:0.8rem"><a href="security_logs.php" class="btn secondary small">View all logs →</a></p>
</div>

<div class="panel">
    <h2 style="margin-top:0">Recent Threat Alerts</h2>
    <table>
        <tr><th>ID</th><th>IP Address</th><th>Threat Type</th><th>Detected</th><th>Status</th></tr>
        <?php foreach ($recentAlerts as $a): ?>
        <tr>
            <td>#<?= $a['alert_id'] ?></td>
            <td><?= e($a['ip_address']) ?></td>
            <td><?= e($a['threat_type']) ?></td>
            <td><?= e($a['detected_at']) ?></td>
            <td><?= $a['resolved'] ? '<span class="badge badge-success">Resolved</span>' : '<span class="badge badge-fail">Open</span>' ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>

<?php require 'includes/footer.php'; ?>
