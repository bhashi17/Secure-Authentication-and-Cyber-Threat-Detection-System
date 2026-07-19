-- =====================================================================
-- 06_bulk_dummy_data.sql   (CORRECTED VERSION)
--
-- Loads ~5,000 rows into every core table so the PHP UI, indexing demo,
-- and procedure/trigger tests all have realistic volume to work with.
--
-- Matches the ACTUAL schema in 01_schema.sql:
--   roles, users, login_attempts, security_logs, blocked_ips,
--   audit_records, sessions, threat_alerts
--
-- The previous version of this file targeted table names from an
-- unrelated draft schema (threat_logs / security_alerts / audit_logs)
-- and never matched 01_schema.sql -- that mismatch is why security_logs
-- (and the other tables) showed 0 rows in the app. This version fixes
-- that by inserting into the correct tables/columns only.
--
-- Run AFTER 01_schema.sql, 02_seed_data.sql, 03_indexing.sql,
-- 04_procedures_functions_triggers.sql have already been run once:
--   psql -U postgres -d secure_auth_system -f sql/06_bulk_dummy_data.sql
--
-- NOTE: login_attempts has an AFTER INSERT trigger (trg_flag_failed_login)
-- that may add a handful of *extra* security_logs rows on its own when a
-- randomly repeated IP happens to rack up 5+ failed attempts within 15
-- minutes. That's expected real-time-detection behaviour, not a bug --
-- your final security_logs count will end up slightly above 5,000.
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------------
-- 1. ROLES -- reference/lookup table, intentionally stays small (4 rows).
--    A "5,000 roles" table would not make sense for this design; the
--    volume requirement instead applies to the transactional/log tables.
-- ---------------------------------------------------------------------
INSERT INTO roles (role_name, description) VALUES
    ('Admin',           'Full system administrator'),
    ('SecurityAnalyst', 'Monitors security logs and threat alerts'),
    ('Auditor',         'Read-only access for compliance review'),
    ('StandardUser',    'Regular application end-user')
ON CONFLICT (role_name) DO NOTHING;

-- ---------------------------------------------------------------------
-- 2. USERS -- 5,000 rows
-- ---------------------------------------------------------------------
INSERT INTO users (username, email, password_hash, full_name, role_id,
                    is_active, failed_login_count, last_login, created_at, updated_at)
SELECT
    'user' || gs,
    'user' || gs || '@example.com',
    md5('password' || gs),
    'Demo User ' || gs,
    (ARRAY[1,2,3,4])[floor(random()*4)+1],
    (random() > 0.05),
    floor(random()*6)::int,
    NOW() - (random() * interval '90 days'),
    NOW() - (random() * interval '365 days'),
    NOW() - (random() * interval '30 days')
FROM generate_series(1, 5000) AS gs
ON CONFLICT (username) DO NOTHING;

-- ---------------------------------------------------------------------
-- 3. LOGIN_ATTEMPTS -- 5,000 rows
--    (fires trg_flag_failed_login; may add a few security_logs rows)
-- ---------------------------------------------------------------------
WITH uids AS (SELECT array_agg(user_id) AS ids FROM users)
INSERT INTO login_attempts (user_id, username_tried, ip_address, is_success, user_agent, attempt_time)
SELECT
    CASE WHEN random() > 0.1
         THEN uids.ids[floor(random()*array_length(uids.ids,1))+1]
         ELSE NULL END,
    'user' || floor(random()*5000+1)::int,
    (floor(random()*223)+1)::int || '.' || floor(random()*255)::int || '.'
        || floor(random()*255)::int || '.' || floor(random()*255)::int,
    (random() > 0.35),
    (ARRAY['Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
           'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2)',
           'Mozilla/5.0 (X11; Linux x86_64)',
           'curl/8.1.2', 'PostmanRuntime/7.32.3'])[floor(random()*5)+1],
    NOW() - (random() * interval '180 days')
FROM generate_series(1, 5000) AS gs, uids;

-- ---------------------------------------------------------------------
-- 4. SECURITY_LOGS -- 5,000 additional manually-inserted rows
--    (on top of whatever trg_flag_failed_login already added above)
-- ---------------------------------------------------------------------
WITH uids AS (SELECT array_agg(user_id) AS ids FROM users)
INSERT INTO security_logs (event_type, severity, description, ip_address, user_id, created_at)
SELECT
    (ARRAY['BRUTE_FORCE','SQL_INJECTION','XSS','UNAUTHORIZED_ACCESS','SUSPICIOUS_LOGIN'])
        [floor(random()*5)+1],
    (ARRAY['LOW','MEDIUM','HIGH','CRITICAL'])[floor(random()*4)+1],
    'Auto-generated dummy security event #' || gs,
    (floor(random()*223)+1)::int || '.' || floor(random()*255)::int || '.'
        || floor(random()*255)::int || '.' || floor(random()*255)::int,
    CASE WHEN random() > 0.2
         THEN uids.ids[floor(random()*array_length(uids.ids,1))+1]
         ELSE NULL END,
    NOW() - (random() * interval '180 days')
FROM generate_series(1, 5000) AS gs, uids;

-- ---------------------------------------------------------------------
-- 5. BLOCKED_IPS -- 5,000 rows, guaranteed-unique 10.x.x.x addresses
--    so they never collide with anything the earlier seed file inserted.
-- ---------------------------------------------------------------------
INSERT INTO blocked_ips (ip_address, reason, blocked_at, blocked_until, is_active)
SELECT
    '10.' || (gs/65536)::int || '.' || ((gs/256)%256)::int || '.' || (gs%256)::int,
    (ARRAY['Multiple failed login attempts','Suspicious traffic pattern',
           'Known malicious IP (threat intel feed)','Automated bot activity',
           'Manual block by security team'])[floor(random()*5)+1],
    NOW() - (random() * interval '180 days'),
    CASE WHEN random() > 0.4 THEN NOW() + (random() * interval '30 days') ELSE NULL END,
    (random() > 0.3)
FROM generate_series(1, 5000) AS gs
ON CONFLICT (ip_address) DO NOTHING;

-- ---------------------------------------------------------------------
-- 6. AUDIT_RECORDS -- 5,000 rows
-- ---------------------------------------------------------------------
WITH uids AS (SELECT array_agg(user_id) AS ids FROM users)
INSERT INTO audit_records (user_id, action, table_affected, record_id, old_value, new_value, action_time)
SELECT
    uids.ids[floor(random()*array_length(uids.ids,1))+1],
    (ARRAY['INSERT','UPDATE','DELETE'])[floor(random()*3)+1],
    (ARRAY['users','blocked_ips','security_logs','login_attempts'])[floor(random()*4)+1],
    floor(random()*5000+1)::int,
    jsonb_build_object('is_active', (random()>0.5), 'failed_login_count', floor(random()*5)::int),
    jsonb_build_object('is_active', (random()>0.5), 'failed_login_count', floor(random()*5)::int),
    NOW() - (random() * interval '180 days')
FROM generate_series(1, 5000) AS gs, uids;

-- ---------------------------------------------------------------------
-- 7. SESSIONS -- 5,000 rows
-- ---------------------------------------------------------------------
WITH uids AS (SELECT array_agg(user_id) AS ids FROM users)
INSERT INTO sessions (user_id, session_token, ip_address, created_at, expires_at, is_valid)
SELECT
    uids.ids[floor(random()*array_length(uids.ids,1))+1],
    md5('session' || gs || random()::text) || gs,
    (floor(random()*223)+1)::int || '.' || floor(random()*255)::int || '.'
        || floor(random()*255)::int || '.' || floor(random()*255)::int,
    NOW() - (random() * interval '60 days'),
    NOW() + (random() * interval '7 days'),
    (random() > 0.25)
FROM generate_series(1, 5000) AS gs, uids;

-- ---------------------------------------------------------------------
-- 8. THREAT_ALERTS -- 5,000 rows
-- ---------------------------------------------------------------------
INSERT INTO threat_alerts (ip_address, threat_type, description, detected_at, resolved, resolved_at)
SELECT
    (floor(random()*223)+1)::int || '.' || floor(random()*255)::int || '.'
        || floor(random()*255)::int || '.' || floor(random()*255)::int,
    (ARRAY['BRUTE_FORCE','SQL_INJECTION','XSS','PORT_SCAN','CREDENTIAL_STUFFING'])
        [floor(random()*5)+1],
    'Correlated threat alert #' || gs || ' raised by monitoring layer',
    NOW() - (random() * interval '180 days'),
    (random() > 0.4),
    CASE WHEN random() > 0.4 THEN NOW() - (random() * interval '90 days') ELSE NULL END
FROM generate_series(1, 5000) AS gs;

COMMIT;

-- ---------------------------------------------------------------------
-- Sanity check -- run this after the script to confirm final row counts
-- ---------------------------------------------------------------------
-- SELECT 'roles' t, COUNT(*) FROM roles
-- UNION ALL SELECT 'users', COUNT(*) FROM users
-- UNION ALL SELECT 'login_attempts', COUNT(*) FROM login_attempts
-- UNION ALL SELECT 'security_logs', COUNT(*) FROM security_logs
-- UNION ALL SELECT 'blocked_ips', COUNT(*) FROM blocked_ips
-- UNION ALL SELECT 'audit_records', COUNT(*) FROM audit_records
-- UNION ALL SELECT 'sessions', COUNT(*) FROM sessions
-- UNION ALL SELECT 'threat_alerts', COUNT(*) FROM threat_alerts;
