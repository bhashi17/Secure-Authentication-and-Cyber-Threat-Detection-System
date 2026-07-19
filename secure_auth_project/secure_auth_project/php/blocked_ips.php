<?php
require 'config.php';
require 'includes/auth.php';
$pageTitle = 'Blocked IPs';

// ---- Add manual block ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add'])) {
    $stmt = $pdo->prepare("
        INSERT INTO blocked_ips (ip_address, reason, blocked_until, is_active)
        VALUES (?, ?, NOW() + (?||' hours')::interval, TRUE)
        ON CONFLICT (ip_address) DO UPDATE SET
            reason = EXCLUDED.reason, blocked_at = NOW(),
            blocked_until = EXCLUDED.blocked_until, is_active = TRUE");
    $stmt->execute([$_POST['ip_address'], $_POST['reason'], (int)$_POST['hours']]);
    header("Location: blocked_ips.php?added=1");
    exit;
}

// ---- Unblock (set inactive) ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['unblock_id'])) {
    $stmt = $pdo->prepare("UPDATE blocked_ips SET is_active = FALSE WHERE block_id = ?");
    $stmt->execute([$_POST['unblock_id']]);
    header("Location: blocked_ips.php?unblocked=1");
    exit;
}

// ---- Delete permanently ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    $stmt = $pdo->prepare("DELETE FROM blocked_ips WHERE block_id = ?");
    $stmt->execute([$_POST['delete_id']]);
    header("Location: blocked_ips.php?deleted=1");
    exit;
}

$onlyActive = isset($_GET['active']) ? $_GET['active'] : '1';
$where = $onlyActive === '1' ? 'WHERE is_active = TRUE' : '';

$rows = $pdo->query("
    SELECT block_id, ip_address, reason, blocked_at, blocked_until, is_active
    FROM blocked_ips $where
    ORDER BY blocked_at DESC
    LIMIT 200
")->fetchAll();

require 'includes/header.php';
?>
<h1>Blocked IPs</h1>
<p class="subtitle">IPs blocked automatically by <code>sp_process_login_attempt</code> / triggers, or manually below.</p>

<?php if (isset($_GET['added'])): ?><div class="alert alert-success">IP blocked.</div><?php endif; ?>
<?php if (isset($_GET['unblocked'])): ?><div class="alert alert-info">IP unblocked.</div><?php endif; ?>
<?php if (isset($_GET['deleted'])): ?><div class="alert alert-success">Record deleted.</div><?php endif; ?>

<div class="panel">
    <h2 style="margin-top:0">Manually Block an IP</h2>
    <form method="post" class="filters">
        <input type="text" name="ip_address" placeholder="e.g. 198.51.100.23" required>
        <input type="text" name="reason" placeholder="Reason" required style="min-width:220px">
        <input type="number" name="hours" placeholder="Block for (hours)" value="24" min="1" style="width:150px">
        <button class="btn" type="submit" name="add" value="1">Block IP</button>
    </form>
</div>

<div class="toolbar">
    <form class="filters" method="get">
        <select name="active" onchange="this.form.submit()">
            <option value="1" <?= $onlyActive==='1'?'selected':'' ?>>Active blocks only</option>
            <option value="0" <?= $onlyActive==='0'?'selected':'' ?>>All (including expired/unblocked)</option>
        </select>
    </form>
</div>

<table>
    <tr><th>ID</th><th>IP Address</th><th>Reason</th><th>Blocked At</th><th>Until</th><th>Status</th><th>Actions</th></tr>
    <?php foreach ($rows as $b): ?>
    <tr>
        <td>#<?= $b['block_id'] ?></td>
        <td><?= e($b['ip_address']) ?></td>
        <td><?= e($b['reason']) ?></td>
        <td><?= e($b['blocked_at']) ?></td>
        <td><?= e($b['blocked_until']) ?: '—' ?></td>
        <td><?= $b['is_active'] ? '<span class="badge badge-fail">Blocked</span>' : '<span class="badge badge-success">Unblocked</span>' ?></td>
        <td>
            <?php if ($b['is_active']): ?>
            <form class="inline" method="post">
                <input type="hidden" name="unblock_id" value="<?= $b['block_id'] ?>">
                <button class="btn small secondary" type="submit">Unblock</button>
            </form>
            <?php endif; ?>
            <form class="inline" method="post" onsubmit="return confirm('Permanently delete this record?');">
                <input type="hidden" name="delete_id" value="<?= $b['block_id'] ?>">
                <button class="btn small danger" type="submit">Delete</button>
            </form>
        </td>
    </tr>
    <?php endforeach; ?>
    <?php if (empty($rows)): ?><tr><td colspan="7" style="text-align:center;color:#94a3b8">No records.</td></tr><?php endif; ?>
</table>

<?php require 'includes/footer.php'; ?>
