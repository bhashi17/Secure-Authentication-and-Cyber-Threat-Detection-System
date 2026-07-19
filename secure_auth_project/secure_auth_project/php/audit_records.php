<?php
require 'config.php';
require 'includes/auth.php';
$pageTitle = 'Audit Trail';

$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = 25;
$offset = ($page - 1) * $perPage;

$totalCount = $pdo->query("SELECT COUNT(*) FROM audit_records")->fetchColumn();
$totalPages = max(1, ceil($totalCount / $perPage));

$stmt = $pdo->prepare("
    SELECT a.audit_id, a.action, a.table_affected, a.record_id, a.old_value, a.new_value,
           a.action_time, u.username AS performed_by
    FROM audit_records a
    LEFT JOIN users u ON u.user_id = a.user_id
    ORDER BY a.action_time DESC
    LIMIT $perPage OFFSET $offset
");
$stmt->execute();
$rows = $stmt->fetchAll();

require 'includes/header.php';
?>
<h1>Audit Trail</h1>
<p class="subtitle"><?= $totalCount ?> audit record(s) - written by <code>sp_deactivate_user</code> and <code>trg_audit_user_update</code>. Read-only by design (this is what the db_auditor role can see).</p>

<table>
    <tr><th>ID</th><th>Performed By</th><th>Action</th><th>Table</th><th>Record ID</th><th>Old Value</th><th>New Value</th><th>Time</th></tr>
    <?php foreach ($rows as $r): ?>
    <tr>
        <td>#<?= $r['audit_id'] ?></td>
        <td><?= e($r['performed_by']) ?: '—' ?></td>
        <td><?= e($r['action']) ?></td>
        <td><?= e($r['table_affected']) ?></td>
        <td><?= e($r['record_id']) ?></td>
        <td><code><?= e($r['old_value']) ?></code></td>
        <td><code><?= e($r['new_value']) ?></code></td>
        <td><?= e($r['action_time']) ?></td>
    </tr>
    <?php endforeach; ?>
</table>

<div class="pagination">
    <?php for ($p = 1; $p <= min($totalPages, 15); $p++): ?>
        <a href="?page=<?= $p ?>" class="<?= $p==$page?'active':'' ?>"><?= $p ?></a>
    <?php endfor; ?>
</div>

<?php require 'includes/footer.php'; ?>
