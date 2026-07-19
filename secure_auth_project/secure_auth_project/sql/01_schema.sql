-- =====================================================================
-- Secure Authentication and Cyber Threat Detection System
-- 01_schema.sql  -  Full database schema (run this first)
-- Database: PostgreSQL 13+
--
-- NOTE: run this AFTER you have already created and connected to the
-- secure_auth_system database, e.g.:
--   psql -U postgres -d secure_auth_system -f 01_schema.sql
-- =====================================================================

-- =====================================================================
-- 1. ROLES  (application-level roles, e.g. Admin / Security Analyst)
-- =====================================================================
CREATE TABLE roles (
    role_id      SERIAL PRIMARY KEY,
    role_name    VARCHAR(50)  NOT NULL UNIQUE,
    description  TEXT,
    created_at   TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- =====================================================================
-- 2. USERS
-- =====================================================================
CREATE TABLE users (
    user_id             SERIAL PRIMARY KEY,
    username             VARCHAR(50)  NOT NULL UNIQUE,
    email                VARCHAR(100) NOT NULL UNIQUE,
    password_hash        VARCHAR(255) NOT NULL,
    full_name            VARCHAR(100) NOT NULL,
    role_id              INT          NOT NULL REFERENCES roles(role_id),
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_login_count   INT          NOT NULL DEFAULT 0,
    last_login           TIMESTAMP,
    created_at           TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- =====================================================================
-- 3. LOGIN ATTEMPTS  (every login attempt, success or fail)
-- =====================================================================
CREATE TABLE login_attempts (
    attempt_id      BIGSERIAL PRIMARY KEY,
    user_id         INT REFERENCES users(user_id) ON DELETE SET NULL,
    username_tried  VARCHAR(50)  NOT NULL,
    ip_address      VARCHAR(45)  NOT NULL,
    is_success      BOOLEAN      NOT NULL,
    user_agent      VARCHAR(255),
    attempt_time    TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- =====================================================================
-- 4. SECURITY LOGS  (detected security-relevant events)
-- =====================================================================
CREATE TABLE security_logs (
    log_id       BIGSERIAL PRIMARY KEY,
    event_type   VARCHAR(50)  NOT NULL,   -- BRUTE_FORCE, SQL_INJECTION, XSS, UNAUTHORIZED_ACCESS, SUSPICIOUS_LOGIN
    severity     VARCHAR(20)  NOT NULL,   -- LOW, MEDIUM, HIGH, CRITICAL
    description  TEXT,
    ip_address   VARCHAR(45),
    user_id      INT REFERENCES users(user_id) ON DELETE SET NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- =====================================================================
-- 5. BLOCKED IPS
-- =====================================================================
CREATE TABLE blocked_ips (
    block_id       SERIAL PRIMARY KEY,
    ip_address     VARCHAR(45)  NOT NULL UNIQUE,
    reason         TEXT,
    blocked_at     TIMESTAMP    NOT NULL DEFAULT NOW(),
    blocked_until  TIMESTAMP,
    is_active      BOOLEAN      NOT NULL DEFAULT TRUE
);

-- =====================================================================
-- 6. AUDIT RECORDS  (who changed what, before/after values)
-- =====================================================================
CREATE TABLE audit_records (
    audit_id        BIGSERIAL PRIMARY KEY,
    user_id         INT REFERENCES users(user_id) ON DELETE SET NULL,
    action          VARCHAR(50)  NOT NULL,   -- INSERT, UPDATE, DELETE
    table_affected  VARCHAR(50)  NOT NULL,
    record_id       INT,
    old_value       JSONB,
    new_value       JSONB,
    action_time     TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- =====================================================================
-- 7. SESSIONS  (active login sessions/tokens)
-- =====================================================================
CREATE TABLE sessions (
    session_id      BIGSERIAL PRIMARY KEY,
    user_id         INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    session_token   VARCHAR(255) NOT NULL UNIQUE,
    ip_address      VARCHAR(45),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    is_valid        BOOLEAN NOT NULL DEFAULT TRUE
);

-- =====================================================================
-- 8. THREAT ALERTS  (higher-level correlated alerts for the dashboard)
-- =====================================================================
CREATE TABLE threat_alerts (
    alert_id      BIGSERIAL PRIMARY KEY,
    ip_address    VARCHAR(45) NOT NULL,
    threat_type   VARCHAR(50) NOT NULL,     -- BRUTE_FORCE, SQL_INJECTION, XSS, PORT_SCAN, CREDENTIAL_STUFFING
    description   TEXT,
    detected_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    resolved      BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at   TIMESTAMP
);

-- =====================================================================
-- Base reference data (application roles used by the use case diagram)
-- =====================================================================
INSERT INTO roles (role_name, description) VALUES
    ('Admin',            'Full system administrator - manages users, roles, blocked IPs and configuration'),
    ('SecurityAnalyst',  'Monitors security logs, threat alerts and investigates incidents'),
    ('Auditor',          'Read-only access to logs and audit trail for compliance review'),
    ('StandardUser',     'Regular application end-user, authenticates and uses the protected app');

COMMENT ON TABLE users IS 'Application users protected by the authentication layer';
COMMENT ON TABLE login_attempts IS 'Every authentication attempt made against the system';
COMMENT ON TABLE security_logs IS 'Security events detected by the monitoring layer';
COMMENT ON TABLE blocked_ips IS 'IP addresses currently or previously blocked';
COMMENT ON TABLE audit_records IS 'Before/after audit trail of sensitive data changes';