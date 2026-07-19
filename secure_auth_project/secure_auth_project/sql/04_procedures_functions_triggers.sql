-- =====================================================================
-- 04_procedures_functions_triggers.sql
-- Project Report Part 2 - Stored Procedures, Functions, Triggers
-- Run 01_schema.sql, 02_seed_data.sql, 03_indexing.sql first.
-- =====================================================================


-- =====================================================================
-- FUNCTION 1
-- Purpose : Count failed login attempts from a given IP within the last
--           N minutes.
-- Why it matters: Both the brute-force trigger and the login procedure
--   need this exact calculation. Wrapping it in one function avoids
--   duplicating the logic and keeps the "5 failed attempts = brute
--   force" threshold defined in a single place.
-- =====================================================================
CREATE OR REPLACE FUNCTION fn_get_failed_attempts(
    p_ip_address VARCHAR,
    p_minutes    INT
) RETURNS INT AS $$
DECLARE
    v_count INT;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM login_attempts
    WHERE ip_address = p_ip_address
      AND is_success = FALSE
      AND attempt_time >= NOW() - (p_minutes || ' minutes')::INTERVAL;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Test:
-- SELECT fn_get_failed_attempts('185.220.101.5', 15);


-- =====================================================================
-- FUNCTION 2
-- Purpose : Check whether an IP address is currently blocked (active
--           and, if it has an expiry, not yet expired).
-- Why it matters: The PHP authentication layer must call this on every
--   single login page load before it even shows the login form. Having
--   it as one reusable boolean function keeps that check consistent
--   everywhere in the app instead of re-writing the same WHERE clause.
-- =====================================================================
CREATE OR REPLACE FUNCTION fn_is_ip_blocked(
    p_ip_address VARCHAR
) RETURNS BOOLEAN AS $$
DECLARE
    v_blocked BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM blocked_ips
        WHERE ip_address = p_ip_address
          AND is_active = TRUE
          AND (blocked_until IS NULL OR blocked_until > NOW())
    ) INTO v_blocked;

    RETURN v_blocked;
END;
$$ LANGUAGE plpgsql;

-- Test:
-- SELECT fn_is_ip_blocked('91.240.118.3');


-- =====================================================================
-- STORED PROCEDURE 1  (uses an explicit transaction)
-- Purpose : Process one login attempt end-to-end: log it, update the
--           user's failed_login_count / last_login, and if the number
--           of recent failures from that IP crosses the threshold,
--           automatically block the IP and raise a security log entry.
-- Why it matters: This is the core of the "cyber threat detection"
--   feature. It must be atomic - either the login attempt, the user
--   update, AND the (possible) auto-block all succeed together, or
--   none of them do, so the system is never left in a half-updated,
--   inconsistent state (e.g. an IP blocked but no log explaining why).
-- =====================================================================
CREATE OR REPLACE PROCEDURE sp_process_login_attempt(
    p_username   VARCHAR,
    p_ip_address VARCHAR,
    p_success    BOOLEAN,
    p_user_agent VARCHAR
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id      INT;
    v_fail_count   INT;
BEGIN
    -- Everything below runs as one transaction (a CALL to a procedure
    -- is transactional by default in PostgreSQL).

    SELECT user_id INTO v_user_id FROM users WHERE username = p_username;

    INSERT INTO login_attempts (user_id, username_tried, ip_address, is_success, user_agent)
    VALUES (v_user_id, p_username, p_ip_address, p_success, p_user_agent);

    IF p_success THEN
        UPDATE users
           SET failed_login_count = 0,
               last_login = NOW(),
               updated_at = NOW()
         WHERE user_id = v_user_id;
    ELSE
        UPDATE users
           SET failed_login_count = failed_login_count + 1,
               updated_at = NOW()
         WHERE user_id = v_user_id;

        v_fail_count := fn_get_failed_attempts(p_ip_address, 15);

        IF v_fail_count >= 5 THEN
            INSERT INTO blocked_ips (ip_address, reason, blocked_until, is_active)
            VALUES (
                p_ip_address,
                'Automatic block: ' || v_fail_count || ' failed logins within 15 minutes',
                NOW() + INTERVAL '24 hours',
                TRUE
            )
            ON CONFLICT (ip_address) DO UPDATE
                SET is_active = TRUE,
                    blocked_at = NOW(),
                    blocked_until = NOW() + INTERVAL '24 hours',
                    reason = EXCLUDED.reason;

            INSERT INTO security_logs (event_type, severity, description, ip_address, user_id)
            VALUES (
                'BRUTE_FORCE',
                'CRITICAL',
                v_fail_count || ' failed login attempts detected from ' || p_ip_address || ' - IP auto-blocked',
                p_ip_address,
                v_user_id
            );
        END IF;
    END IF;

    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;
        RAISE NOTICE 'sp_process_login_attempt failed: %', SQLERRM;
END;
$$;

-- Test:
-- CALL sp_process_login_attempt('user1', '185.220.101.5', FALSE, 'TestAgent/1.0');
-- SELECT * FROM login_attempts ORDER BY attempt_id DESC LIMIT 1;


-- =====================================================================
-- STORED PROCEDURE 2  (uses an explicit transaction)
-- Purpose : Deactivate a user account (e.g. compromised account, policy
--           violation) and write a matching audit record in the same
--           transaction.
-- Why it matters: Deactivating a user is a security-sensitive action.
--   It must never happen "silently" - the audit_records row proving
--   who deactivated the account, when, and what changed must be
--   written atomically with the deactivation itself, otherwise the
--   system could show a deactivated account with no accountability
--   trail (a compliance failure for Part 3's role/privilege review).
-- =====================================================================
CREATE OR REPLACE PROCEDURE sp_deactivate_user(
    p_user_id  INT,
    p_admin_id INT,
    p_reason   VARCHAR
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_active BOOLEAN;
    v_old_failed INT;
BEGIN
    SELECT is_active, failed_login_count INTO v_old_active, v_old_failed
    FROM users WHERE user_id = p_user_id
    FOR UPDATE;

    IF v_old_active IS NULL THEN
        RAISE EXCEPTION 'User % does not exist', p_user_id;
    END IF;

    UPDATE users
       SET is_active = FALSE,
           updated_at = NOW()
     WHERE user_id = p_user_id;

    INSERT INTO audit_records (user_id, action, table_affected, record_id, old_value, new_value)
    VALUES (
        p_admin_id,
        'UPDATE',
        'users',
        p_user_id,
        jsonb_build_object('is_active', v_old_active, 'failed_login_count', v_old_failed),
        jsonb_build_object('is_active', FALSE, 'reason', p_reason)
    );

    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;
        RAISE NOTICE 'sp_deactivate_user failed: %', SQLERRM;
END;
$$;

-- Test:
-- CALL sp_deactivate_user(50, 1, 'Suspicious activity reported by security analyst');
-- SELECT * FROM audit_records ORDER BY audit_id DESC LIMIT 1;


-- =====================================================================
-- TRIGGER 1
-- Purpose : Whenever a user row is UPDATEd, automatically write an
--           audit_records entry comparing old vs new values.
-- Why it matters: Admins/analysts can also edit users directly through
--   the PHP CRUD "Edit User" screen (not just through sp_deactivate_user).
--   The trigger guarantees that EVERY update to the users table is
--   captured in the audit trail, regardless of which code path made
--   the change - closing the gap that a procedure alone can't cover.
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_fn_audit_user_update() RETURNS TRIGGER AS $$
BEGIN
    IF (OLD.is_active, OLD.failed_login_count, OLD.role_id, OLD.email) IS DISTINCT FROM
       (NEW.is_active, NEW.failed_login_count, NEW.role_id, NEW.email) THEN

        INSERT INTO audit_records (user_id, action, table_affected, record_id, old_value, new_value)
        VALUES (
            NEW.user_id,
            'UPDATE',
            'users',
            NEW.user_id,
            jsonb_build_object('is_active', OLD.is_active, 'failed_login_count', OLD.failed_login_count,
                                'role_id', OLD.role_id, 'email', OLD.email),
            jsonb_build_object('is_active', NEW.is_active, 'failed_login_count', NEW.failed_login_count,
                                'role_id', NEW.role_id, 'email', NEW.email)
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_user_update
AFTER UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION trg_fn_audit_user_update();

-- Test:
-- UPDATE users SET is_active = FALSE WHERE user_id = 10;
-- SELECT * FROM audit_records WHERE record_id = 10 ORDER BY audit_id DESC;


-- =====================================================================
-- TRIGGER 2
-- Purpose : Whenever a FAILED login attempt is inserted, immediately
--           check if that IP has crossed the brute-force threshold and,
--           if so, write a security_logs entry - even if the row was
--           inserted directly (e.g. by another module) and not through
--           sp_process_login_attempt.
-- Why it matters: Real-time threat detection must not depend on every
--   caller remembering to invoke the procedure. A trigger on the raw
--   table guarantees detection fires no matter how the row got there,
--   which is the whole point of the "detect in real time" requirement.
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_fn_flag_failed_login() RETURNS TRIGGER AS $$
DECLARE
    v_fail_count INT;
BEGIN
    IF NEW.is_success = FALSE THEN
        v_fail_count := fn_get_failed_attempts(NEW.ip_address, 15);

        IF v_fail_count >= 5 AND NOT fn_is_ip_blocked(NEW.ip_address) THEN
            INSERT INTO security_logs (event_type, severity, description, ip_address, user_id)
            VALUES (
                'BRUTE_FORCE',
                'HIGH',
                v_fail_count || ' failed logins from ' || NEW.ip_address || ' in the last 15 minutes (trigger-detected)',
                NEW.ip_address,
                NEW.user_id
            );
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_flag_failed_login
AFTER INSERT ON login_attempts
FOR EACH ROW
EXECUTE FUNCTION trg_fn_flag_failed_login();

-- Test:
-- INSERT INTO login_attempts (username_tried, ip_address, is_success, user_agent)
-- VALUES ('user2', '203.0.113.99', FALSE, 'TestAgent/1.0');
-- (repeat 5 times with the same IP, then check security_logs)
