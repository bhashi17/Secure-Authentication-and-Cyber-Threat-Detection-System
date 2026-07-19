<?php
require 'config.php';
require 'includes/auth.php';

$id = $_GET['id'] ?? null;
$isEdit = !empty($id);
$pageTitle = $isEdit ? 'Edit User' : 'Add User';
$error = '';

$roles = $pdo->query("SELECT role_id, role_name FROM roles ORDER BY role_id")->fetchAll();

$user = [
    'username' => '', 'email' => '', 'full_name' => '',
    'role_id' => 4, 'is_active' => true,
];

if ($isEdit) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
    $stmt->execute([$id]);
    $user = $stmt->fetch();
    if (!$user) { die("User not found."); }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email    = trim($_POST['email']);
    $fullName = trim($_POST['full_name']);
    $roleId   = (int)$_POST['role_id'];
    $isActive = isset($_POST['is_active']);
    $password = $_POST['password'] ?? '';

    if ($username === '' || $email === '' || $fullName === '') {
        $error = 'Username, email and full name are required.';
    } else {
        try {
            if ($isEdit) {
                if ($password !== '') {
                    $stmt = $pdo->prepare("
                        UPDATE users SET username=?, email=?, full_name=?, role_id=?, is_active=?,
                               password_hash=?, updated_at=NOW()
                        WHERE user_id=?");
                    $stmt->execute([$username, $email, $fullName, $roleId, $isActive, md5($password), $id]);
                } else {
                    $stmt = $pdo->prepare("
                        UPDATE users SET username=?, email=?, full_name=?, role_id=?, is_active=?, updated_at=NOW()
                        WHERE user_id=?");
                    $stmt->execute([$username, $email, $fullName, $roleId, $isActive, $id]);
                }
            } else {
                if ($password === '') { $password = 'ChangeMe123!'; }
                $stmt = $pdo->prepare("
                    INSERT INTO users (username, email, full_name, role_id, is_active, password_hash)
                    VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$username, $email, $fullName, $roleId, $isActive, md5($password)]);
            }
            header("Location: users.php?saved=1");
            exit;
        } catch (PDOException $e) {
            $error = 'Could not save user: ' . $e->getMessage();
        }
    }
    // keep entered values on error
    $user = ['username'=>$username,'email'=>$email,'full_name'=>$fullName,'role_id'=>$roleId,'is_active'=>$isActive];
}

require 'includes/header.php';
?>
<h1><?= $isEdit ? 'Edit User #' . e($id) : 'Add New User' ?></h1>
<p class="subtitle">Note: passwords are hashed with MD5 here purely as a coursework placeholder for a real bcrypt/Argon2 hash.</p>

<?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>

<div class="panel" style="max-width:520px">
    <form method="post">
        <div class="field">
            <label>Username</label>
            <input type="text" name="username" value="<?= e($user['username']) ?>" required style="width:100%">
        </div>
        <div class="field">
            <label>Full Name</label>
            <input type="text" name="full_name" value="<?= e($user['full_name']) ?>" required style="width:100%">
        </div>
        <div class="field">
            <label>Email</label>
            <input type="email" name="email" value="<?= e($user['email']) ?>" required style="width:100%">
        </div>
        <div class="field">
            <label>Role</label>
            <select name="role_id" style="width:100%">
                <?php foreach ($roles as $r): ?>
                    <option value="<?= $r['role_id'] ?>" <?= $r['role_id']==$user['role_id']?'selected':'' ?>>
                        <?= e($r['role_name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="field">
            <label><?= $isEdit ? 'New Password (leave blank to keep current)' : 'Password (blank = default ChangeMe123!)' ?></label>
            <input type="password" name="password" style="width:100%">
        </div>
        <div class="field">
            <label><input type="checkbox" name="is_active" <?= $user['is_active'] ? 'checked' : '' ?>> Account Active</label>
        </div>
        <button class="btn" type="submit"><?= $isEdit ? 'Save Changes' : 'Create User' ?></button>
        <a href="users.php" class="btn secondary">Cancel</a>
    </form>
</div>

<?php require 'includes/footer.php'; ?>
