<?php
require 'config.php';
require 'includes/auth.php';
$pageTitle = 'Users';

// ---- Handle delete ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
    $stmt->execute([$_POST['delete_id']]);
    header("Location: users.php?deleted=1");
    exit;
}

// ---- Search + pagination ----
$search = trim($_GET['q'] ?? '');
$page   = max(1, (int)($_GET['page'] ?? 1));
$perPage = 20;
$offset = ($page - 1) * $perPage;

$where = '';
$params = [];
if ($search !== '') {
    $where = "WHERE u.username ILIKE ? OR u.email ILIKE ? OR u.full_name ILIKE ?";
    $params = ["%$search%", "%$search%", "%$search%"];
}

$total = $pdo->prepare("SELECT COUNT(*) FROM users u $where");
$total->execute($params);
$totalCount = $total->fetchColumn();
$totalPages = max(1, ceil($totalCount / $perPage));

$sql = "
    SELECT u.user_id, u.username, u.email, u.full_name, u.is_active, u.failed_login_count,
           u.last_login, r.role_name
    FROM users u
    JOIN roles r ON r.role_id = u.role_id
    $where
    ORDER BY u.user_id
    LIMIT $perPage OFFSET $offset
";
$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$users = $stmt->fetchAll();

require 'includes/header.php';
?>
<h1>Users</h1>
<p class="subtitle">Full CRUD - <?= $totalCount ?> user(s) total.</p>

<?php if (isset($_GET['deleted'])): ?><div class="alert alert-success">User deleted.</div><?php endif; ?>
<?php if (isset($_GET['saved'])): ?><div class="alert alert-success">User saved.</div><?php endif; ?>

<div class="toolbar">
    <form class="filters" method="get">
        <input type="text" name="q" placeholder="Search username / email / name" value="<?= e($search) ?>">
        <button class="btn secondary" type="submit">Search</button>
    </form>
    <a href="user_form.php" class="btn">+ Add User</a>
</div>

<table>
    <tr>
        <th>ID</th><th>Username</th><th>Full Name</th><th>Email</th><th>Role</th>
        <th>Status</th><th>Failed Logins</th><th>Last Login</th><th>Actions</th>
    </tr>
    <?php foreach ($users as $u): ?>
    <tr>
        <td>#<?= $u['user_id'] ?></td>
        <td><?= e($u['username']) ?></td>
        <td><?= e($u['full_name']) ?></td>
        <td><?= e($u['email']) ?></td>
        <td><?= e($u['role_name']) ?></td>
        <td><?= $u['is_active'] ? '<span class="badge badge-active">Active</span>' : '<span class="badge badge-inactive">Inactive</span>' ?></td>
        <td><?= $u['failed_login_count'] ?></td>
        <td><?= e($u['last_login']) ?: '—' ?></td>
        <td>
            <a class="btn small secondary" href="user_form.php?id=<?= $u['user_id'] ?>">Edit</a>
            <form class="inline" method="post" onsubmit="return confirm('Delete this user permanently?');">
                <input type="hidden" name="delete_id" value="<?= $u['user_id'] ?>">
                <button class="btn small danger" type="submit">Delete</button>
            </form>
        </td>
    </tr>
    <?php endforeach; ?>
    <?php if (empty($users)): ?>
    <tr><td colspan="9" style="text-align:center;color:#94a3b8">No users found.</td></tr>
    <?php endif; ?>
</table>

<div class="pagination">
    <?php for ($p = 1; $p <= $totalPages; $p++): ?>
        <a href="?page=<?= $p ?>&q=<?= urlencode($search) ?>" class="<?= $p==$page?'active':'' ?>"><?= $p ?></a>
    <?php endfor; ?>
</div>

<?php require 'includes/footer.php'; ?>
