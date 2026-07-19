-- =====================================================================
-- 02_seed_data.sql
-- Generates ~5,300 realistic dummy rows across all tables.
-- Run AFTER 01_schema.sql. Safe to re-run (it truncates first).
-- =====================================================================

TRUNCATE threat_alerts, sessions, audit_records, blocked_ips,
         security_logs, login_attempts, users RESTART IDENTITY CASCADE;

-- ---------------------------------------------------------------------
-- Helper: random IPv4 address as text
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION _random_ip() RETURNS VARCHAR AS $$
BEGIN
    RETURN (floor(random()*223)+1)::text || '.' ||
           (floor(random()*255))::text || '.' ||
           (floor(random()*255))::text || '.' ||
           (floor(random()*255)+1)::text;
END;
$$ LANGUAGE plpgsql;

-- =====================================================================
-- USERS  (250 rows)
-- =====================================================================
INSERT INTO users (username, email, password_hash, full_name, role_id, is_active, failed_login_count, last_login, created_at)
SELECT
    'user' || g,
    'user' || g || '@example.com',
    md5('password' || g || 'salt'),                 -- dummy bcrypt-like hash
    (ARRAY['Nimal Perera','Kamal Silva','Anusha Fernando','Dilani Jayasuriya','Ruwan Bandara',
           'Sanduni Wickramasinghe','Tharindu Kumara','Ishara Gunawardena','Chathura Rathnayake',
           'Nadeesha Weerasinghe'])[floor(random()*10)+1] || ' ' || g,
    CASE
        WHEN g <= 5   THEN 1  -- 5 Admins
        WHEN g <= 20  THEN 2  -- 15 Security Analysts
        WHEN g <= 35  THEN 3  -- 15 Auditors
        ELSE 4                -- rest StandardUser
    END,
    (random() > 0.06),                               -- ~94% active
    floor(random()*4),
    NOW() - (random()*90)::int * INTERVAL '1 day',
    NOW() - (random()*365)::int * INTERVAL '1 day'
FROM generate_series(1, 250) AS g;

-- =====================================================================
-- LOGIN ATTEMPTS  (3,500 rows) - mix of success/fail, some from same
-- "attacker" IPs to make brute-force patterns realistic
-- =====================================================================
INSERT INTO login_attempts (user_id, username_tried, ip_address, is_success, user_agent, attempt_time)
SELECT
    CASE WHEN random() > 0.15 THEN u.user_id ELSE NULL END,
    u.username,
    CASE
        WHEN random() < 0.12
            THEN (ARRAY['185.220.101.5','45.155.204.7','193.35.18.20','91.240.118.3','103.94.44.10'])[floor(random()*5)+1]
        ELSE _random_ip()
    END,
    (random() > 0.30),                               -- ~70% success overall
    (ARRAY['Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
           'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
           'Mozilla/5.0 (X11; Linux x86_64)',
           'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'])[floor(random()*4)+1],
    NOW() - (random()*180)::int * INTERVAL '1 day' - (random()*24)::int * INTERVAL '1 hour'
FROM generate_series(1, 3500) AS s
JOIN users u ON u.user_id = (floor(random()*250)+1);

-- =====================================================================
-- SECURITY LOGS  (700 rows)
-- =====================================================================
INSERT INTO security_logs (event_type, severity, description, ip_address, user_id, created_at)
SELECT
    et,
    CASE et
        WHEN 'BRUTE_FORCE'          THEN (ARRAY['MEDIUM','HIGH','CRITICAL'])[floor(random()*3)+1]
        WHEN 'SQL_INJECTION'        THEN (ARRAY['HIGH','CRITICAL'])[floor(random()*2)+1]
        WHEN 'XSS'                  THEN (ARRAY['MEDIUM','HIGH'])[floor(random()*2)+1]
        WHEN 'UNAUTHORIZED_ACCESS'  THEN (ARRAY['MEDIUM','HIGH'])[floor(random()*2)+1]
        ELSE (ARRAY['LOW','MEDIUM'])[floor(random()*2)+1]
    END,
    CASE et
        WHEN 'BRUTE_FORCE'          THEN 'Multiple failed login attempts detected from same source'
        WHEN 'SQL_INJECTION'        THEN 'Suspicious SQL syntax detected in request payload'
        WHEN 'XSS'                  THEN 'Script tag detected in submitted form input'
        WHEN 'UNAUTHORIZED_ACCESS'  THEN 'Attempt to access restricted resource without privilege'
        ELSE 'Login from unusual location/device flagged as suspicious'
    END,
    _random_ip(),
    CASE WHEN random() > 0.4 THEN (floor(random()*250)+1)::int ELSE NULL END,
    NOW() - (random()*180)::int * INTERVAL '1 day'
FROM (
    SELECT (ARRAY['BRUTE_FORCE','SQL_INJECTION','XSS','UNAUTHORIZED_ACCESS','SUSPICIOUS_LOGIN'])[floor(random()*5)+1] AS et
    FROM generate_series(1, 700)
) x;

-- =====================================================================
-- BLOCKED IPS  (150 rows)
-- =====================================================================
INSERT INTO blocked_ips (ip_address, reason, blocked_at, blocked_until, is_active)
SELECT DISTINCT ON (ip)
    ip,
    (ARRAY['Exceeded failed login threshold','Detected SQL injection pattern',
           'Detected XSS payload in request','Known malicious IP (threat feed)',
           'Excessive request rate / possible DoS'])[floor(random()*5)+1],
    ts,
    ts + (INTERVAL '1 hour' * (floor(random()*72)+1)),
    (random() > 0.35)
FROM (
    SELECT _random_ip() AS ip,
           NOW() - (random()*180)::int * INTERVAL '1 day' AS ts
    FROM generate_series(1, 200)
) x
LIMIT 150;

-- =====================================================================
-- AUDIT RECORDS  (300 rows)
-- =====================================================================
INSERT INTO audit_records (user_id, action, table_affected, record_id, old_value, new_value, action_time)
SELECT
    (floor(random()*5)+1)::int,                       -- performed by an Admin (user_id 1-5)
    act,
    'users',
    target_id,
    jsonb_build_object('is_active', NOT new_active, 'failed_login_count', floor(random()*5)),
    jsonb_build_object('is_active', new_active, 'failed_login_count', 0),
    NOW() - (random()*180)::int * INTERVAL '1 day'
FROM (
    SELECT
        (ARRAY['UPDATE','UPDATE','UPDATE','INSERT','DELETE'])[floor(random()*5)+1] AS act,
        (floor(random()*250)+1)::int AS target_id,
        (random() > 0.5) AS new_active
    FROM generate_series(1, 300)
) x;

-- =====================================================================
-- SESSIONS  (200 rows)
-- =====================================================================
INSERT INTO sessions (user_id, session_token, ip_address, created_at, expires_at, is_valid)
SELECT
    (floor(random()*250)+1)::int,
    md5(random()::text || clock_timestamp()::text || s::text),
    _random_ip(),
    created_ts,
    created_ts + INTERVAL '2 hour',
    (random() > 0.2)
FROM (
    SELECT s, NOW() - (random()*60)::int * INTERVAL '1 day' AS created_ts
    FROM generate_series(1, 200) AS s
) x;

-- =====================================================================
-- THREAT ALERTS  (200 rows)
-- =====================================================================
INSERT INTO threat_alerts (ip_address, threat_type, description, detected_at, resolved, resolved_at)
SELECT
    _random_ip(),
    tt,
    'Correlated alert generated from repeated ' || tt || ' events',
    ts,
    is_resolved,
    CASE WHEN is_resolved THEN ts + (INTERVAL '1 hour' * (floor(random()*48)+1)) ELSE NULL END
FROM (
    SELECT
        (ARRAY['BRUTE_FORCE','SQL_INJECTION','XSS','PORT_SCAN','CREDENTIAL_STUFFING'])[floor(random()*5)+1] AS tt,
        NOW() - (random()*180)::int * INTERVAL '1 day' AS ts,
        (random() > 0.45) AS is_resolved
    FROM generate_series(1, 200)
) y;

DROP FUNCTION IF EXISTS _random_ip();

-- =====================================================================
-- Row count summary
-- =====================================================================
SELECT 'users' AS table_name, COUNT(*) FROM users
UNION ALL SELECT 'login_attempts', COUNT(*) FROM login_attempts
UNION ALL SELECT 'security_logs', COUNT(*) FROM security_logs
UNION ALL SELECT 'blocked_ips', COUNT(*) FROM blocked_ips
UNION ALL SELECT 'audit_records', COUNT(*) FROM audit_records
UNION ALL SELECT 'sessions', COUNT(*) FROM sessions
UNION ALL SELECT 'threat_alerts', COUNT(*) FROM threat_alerts;
