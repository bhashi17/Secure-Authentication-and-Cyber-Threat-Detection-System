<?php
require 'config.php';
require 'includes/auth.php';
$pageTitle = 'Security Logs';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    $stmt = $pdo->prepare("DELETE FROM security_logs WHERE log_id = ?");
    $stmt->execute([$_POST['delete_id']]);
    header("Location: security_logs.php?deleted=1");
    exit;
}

$severity = $_GET['severity'] ?? '';
$eventType = $_GET['event_type'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 25;
$offset = ($page - 1) * $perPage;

$conditions = [];
$params = [];
if ($severity !== '') { $conditions[] = "severity = ?"; $params[] = $severity; }
if ($eventType !== '') { $conditions[] = "event_type = ?"; $params[] = $eventType; }
$where = $conditions ? 'WHERE ' . implode(' AND ', $conditions) : '';

$total = $pdo->prepare("SELECT COUNT(*) FROM security_logs $where");
$total->execute($params);
$totalCount = $total->fetchColumn();
$totalPages = max(1, ceil($totalCount / $perPage));

$stmt = $pdo->prepare("
    SELECT log_id, event_type, severity, description, ip_address, user_id, created_at
    FROM security_logs $where
    ORDER BY created_at DESC
    LIMIT $perPage OFFSET $offset
");
$stmt->execute($params);
$logs = $stmt->fetchAll();

$eventTypes = ['BRUTE_FORCE','SQL_INJECTION','XSS','UNAUTHORIZED_ACCESS','SUSPICIOUS_LOGIN'];
$severities = ['LOW','MEDIUM','HIGH','CRITICAL'];

require 'includes/header.php';
?>
<h1>Security Logs</h1>
<p class="subtitle"><?= $totalCount ?> event(s) recorded by the detection layer (procedures + triggers).</p>

<?php if (isset($_GET['deleted'])): ?><div class="alert alert-success">Log entry deleted.</div><?php endif; ?>

<div class="toolbar">
    <form class="filters" method="get">
        <select name="severity">
            <option value="">All severities</option>
            <?php foreach ($severities as $s): ?>
                <option value="<?= $s ?>" <?= $severity===$s?'selected':'' ?>><?= $s ?></option>
            <?php endforeach; ?>
        </select>
        <select name="event_type">
            <option value="">All event types</option>
            <?php foreach ($eventTypes as $t): ?>
                <option value="<?= $t ?>" <?= $eventType===$t?'selected':'' ?>><?= $t ?></option>
            <?php endforeach; ?>
        </select>
        <button class="btn secondary" type="submit">Filter</button>
    </form>
</div>

<table>
    <tr><th>ID</th><th>Event Type</th><th>Severity</th><th>Description</th><th>IP</th><th>User ID</th><th>Time</th><th>Actions</th></tr>
    <?php foreach ($logs as $l): ?>
    <tr>
        <td>#<?= $l['log_id'] ?></td>
        <td><?= e($l['event_type']) ?></td>
        <td><span class="badge badge-<?= e($l['severity']) ?>"><?= e($l['severity']) ?></span></td>
        <td><?= e($l['description']) ?></td>
        <td><?= e($l['ip_address']) ?></td>
        <td><?= $l['user_id'] ? '#'.$l['user_id'] : '—' ?></td>
        <td><?= e($l['created_at']) ?></td>
        <td>
            <form class="inline" method="post" onsubmit="return confirm('Delete this log entry?');">
                <input type="hidden" name="delete_id" value="<?= $l['log_id'] ?>">
                <button class="btn small danger" type="submit">Delete</button>
            </form>
        </td>
    </tr>
    <?php endforeach; ?>
</table>

<div class="pagination">
    <?php for ($p = 1; $p <= min($totalPages, 15); $p++): ?>
        <a href="?page=<?= $p ?>&severity=<?= e($severity) ?>&event_type=<?= e($eventType) ?>" class="<?= $p==$page?'active':'' ?>"><?= $p ?></a>
    <?php endfor; ?>
</div>

<?php require 'includes/footer.php'; ?>
