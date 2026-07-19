<?php
// =====================================================================
// config.php - single place to configure the DB connection.
// Update these 4 values to match your local PostgreSQL setup.
// =====================================================================
$DB_HOST = '127.0.0.1';
$DB_PORT = '2006';
$DB_NAME = 'secure_auth_system';
$DB_USER = 'postgres';        // or 'secadmin1' etc. once roles are created
$DB_PASS = '2006';        // change to your actual postgres password

try {
    $pdo = new PDO(
        "pgsql:host=$DB_HOST;port=$DB_PORT;dbname=$DB_NAME",
        $DB_USER,
        $DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (PDOException $e) {
    die("<div style='font-family:sans-serif;padding:2rem;color:#b91c1c'>
         <h2>Database connection failed</h2><p>" . htmlspecialchars($e->getMessage()) . "</p>
         <p>Check the credentials in <code>php/config.php</code> and make sure PostgreSQL is running
         and the <code>secure_auth_system</code> database has been created from the SQL scripts in
         the <code>sql/</code> folder.</p></div>");
}

// Small helper to keep pages tidy
function e($value) {
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}
