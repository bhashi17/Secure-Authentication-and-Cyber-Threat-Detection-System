<?php
require 'config.php';
require 'includes/auth.php';
$pageTitle = 'Login Attempts';

// ---- Handle insert (this INSERT fires trg_flag_failed_login) ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add'])) {
    $stmt = $pdo->prepare("
        INSERT INTO login_attempts (username_tried, ip_address, is_success, user_agent)
        VALUES (?, ?, ?, ?)");
    $stmt->execute([
        $_POST['username_tried'],
        $_POST['ip_address'],
        isset($_POST['is_success']) ? 't' : 'f',
        $_POST['user_agent'] ?: 'Manual entry (PHP UI)',
    ]);
    header("Location: login_attempts.php?added=1");
    exit;
}

// ---- Handle delete ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE attempt_id = ?");
    $stmt->execute([$_POST['delete_id']]);
    header("Location: login_attempts.php?deleted=1");
    exit;
}

// ---- Filters ----
$ip = trim($_GET['ip'] ?? '');
$status = $_GET['status'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 25;
$offset = ($page - 1) * $perPage;

$conditions = [];
$params = [];
if ($ip !== '') { $conditions[] = "ip_address ILIKE ?"; $params[] = "%$ip%"; }
if ($status === 'success') { $conditions[] = "is_success = TRUE"; }
if ($status === 'failed') { $conditions[] = "is_success = FALSE"; }
$where = $conditions ? 'WHERE ' . implode(' AND ', $conditions) : '';

$total = $pdo->prepare("SELECT COUNT(*) FROM login_attempts $where");
$total->execute($params);
$totalCount = $total->fetchColumn();
$totalPages = max(1, ceil($totalCount / $perPage));

$stmt = $pdo->prepare("
    SELECT attempt_id, username_tried, ip_address, is_success, user_agent, attempt_time
    FROM login_attempts $where
    ORDER BY attempt_time DESC
    LIMIT $perPage OFFSET $offset
");
$stmt->execute($params);
$attempts = $stmt->fetchAll();

require 'includes/header.php';
?>
<h1>Login Attempts</h1>
<p class="subtitle"><?= $totalCount ?> attempt(s) logged. Adding 5+ failed attempts from the same IP within 15 minutes auto-triggers a security log (see <code>trg_flag_failed_login</code>).</p>

<?php if (isset($_GET['added'])): ?><div class="alert alert-success">Attempt recorded. Check Security Logs if this crossed the brute-force threshold.</div><?php endif; ?>
<?php if (isset($_GET['deleted'])): ?><div class="alert alert-success">Attempt deleted.</div><?php endif; ?>

<div class="panel">
    <h2 style="margin-top:0">Record a Login Attempt (manual test / viva demo)</h2>
    <form method="post" class="filters">
        <input type="text" name="username_tried" placeholder="username" required>
        <input type="text" name="ip_address" placeholder="e.g. 203.0.113.99" required>
        <label style="display:flex;align-items:center;gap:0.4rem;color:#e2e8f0"><input type="checkbox" name="is_success"> Success</label>
        <input type="text" name="user_agent" placeholder="user agent (optional)">
        <button class="btn" type="submit" name="add" value="1">Record Attempt</button>
    </form>
</div>

<div class="toolbar">
    <form class="filters" method="get">
        <input type="text" name="ip" placeholder="Filter by IP" value="<?= e($ip) ?>">
        <select name="status">
            <option value="">All statuses</option>
            <option value="success" <?= $status==='success'?'selected':'' ?>>Success only</option>
            <option value="failed" <?= $status==='failed'?'selected':'' ?>>Failed only</option>
        </select>
        <button class="btn secondary" type="submit">Filter</button>
    </form>
</div>

<table>
    <tr><th>ID</th><th>Username</th><th>IP Address</th><th>Result</th><th>User Agent</th><th>Time</th><th>Actions</th></tr>
    <?php foreach ($attempts as $a): ?>
    <tr>
        <td>#<?= $a['attempt_id'] ?></td>
        <td><?= e($a['username_tried']) ?></td>
        <td><?= e($a['ip_address']) ?></td>
        <td><?= $a['is_success'] ? '<span class="badge badge-success">Success</span>' : '<span class="badge badge-fail">Failed</span>' ?></td>
        <td><?= e($a['user_agent']) ?></td>
        <td><?= e($a['attempt_time']) ?></td>
        <td>
            <form class="inline" method="post" onsubmit="return confirm('Delete this record?');">
                <input type="hidden" name="delete_id" value="<?= $a['attempt_id'] ?>">
                <button class="btn small danger" type="submit">Delete</button>
            </form>
        </td>
    </tr>
    <?php endforeach; ?>
</table>

<div class="pagination">
    <?php for ($p = 1; $p <= min($totalPages, 15); $p++): ?>
        <a href="?page=<?= $p ?>&ip=<?= urlencode($ip) ?>&status=<?= e($status) ?>" class="<?= $p==$page?'active':'' ?>"><?= $p ?></a>
    <?php endfor; ?>
</div>

<?php require 'includes/footer.php'; ?>
