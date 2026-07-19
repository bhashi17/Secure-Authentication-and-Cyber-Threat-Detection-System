-- =====================================================================
-- 05_roles_security.sql
-- Project Report Part 3 - Database Security (Roles & Privileges)
--
-- These are POSTGRESQL SERVER-LEVEL roles/users (login roles), separate
-- from the application-level "roles" table (Admin/SecurityAnalyst/
-- Auditor/StandardUser) created in 01_schema.sql. They are aligned to
-- the same two actor groups used in the use case diagram:
--   - db_security_admin : the "Admin" actor - full data control
--   - db_auditor        : the "Auditor"/"SecurityAnalyst" actor -
--                         read-only access to logs and audit trail
-- =====================================================================

-- ---------------------------------------------------------------------
-- GROUP ROLE 1: db_security_admin
-- Privileges: full read/write on all application tables, can execute
-- all procedures/functions. Represents Admin / SecurityAnalyst actors
-- who must be able to manage users, unblock IPs, resolve alerts, etc.
-- ---------------------------------------------------------------------
CREATE ROLE db_security_admin NOLOGIN;

GRANT CONNECT ON DATABASE secure_auth_system TO db_security_admin;
GRANT USAGE ON SCHEMA public TO db_security_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO db_security_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO db_security_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO db_security_admin;
GRANT EXECUTE ON ALL PROCEDURES IN SCHEMA public TO db_security_admin;

-- 4 login users under the db_security_admin group
CREATE ROLE secadmin1 LOGIN PASSWORD 'ChangeMe_SA1!' IN ROLE db_security_admin;
CREATE ROLE secadmin2 LOGIN PASSWORD 'ChangeMe_SA2!' IN ROLE db_security_admin;
CREATE ROLE secadmin3 LOGIN PASSWORD 'ChangeMe_SA3!' IN ROLE db_security_admin;
CREATE ROLE secadmin4 LOGIN PASSWORD 'ChangeMe_SA4!' IN ROLE db_security_admin;

-- ---------------------------------------------------------------------
-- GROUP ROLE 2: db_auditor
-- Privileges: READ-ONLY on logs/audit tables only (login_attempts,
-- security_logs, audit_records, threat_alerts, blocked_ips). No access
-- to write operations, and no SELECT on users.password_hash - auditors
-- review activity, they do not manage accounts or see credentials.
-- ---------------------------------------------------------------------
CREATE ROLE db_auditor NOLOGIN;

GRANT CONNECT ON DATABASE secure_auth_system TO db_auditor;
GRANT USAGE ON SCHEMA public TO db_auditor;
GRANT SELECT ON login_attempts, security_logs, audit_records, threat_alerts, blocked_ips TO db_auditor;

-- Auditors may see user metadata for context, but never the password hash
GRANT SELECT (user_id, username, email, full_name, role_id, is_active, last_login, created_at)
    ON users TO db_auditor;

-- 4 login users under the db_auditor group
CREATE ROLE auditor1 LOGIN PASSWORD 'ChangeMe_AU1!' IN ROLE db_auditor;
CREATE ROLE auditor2 LOGIN PASSWORD 'ChangeMe_AU2!' IN ROLE db_auditor;
CREATE ROLE auditor3 LOGIN PASSWORD 'ChangeMe_AU3!' IN ROLE db_auditor;
CREATE ROLE auditor4 LOGIN PASSWORD 'ChangeMe_AU4!' IN ROLE db_auditor;

-- ---------------------------------------------------------------------
-- Verification queries for your report screenshots
-- ---------------------------------------------------------------------
-- List roles and whether they can log in:
-- SELECT rolname, rolcanlogin, rolsuper FROM pg_roles
--   WHERE rolname LIKE 'secadmin%' OR rolname LIKE 'auditor%'
--      OR rolname IN ('db_security_admin','db_auditor');

-- Show table-level privileges granted to each group role:
-- SELECT grantee, table_name, privilege_type
-- FROM information_schema.role_table_grants
-- WHERE grantee IN ('db_security_admin','db_auditor')
-- ORDER BY grantee, table_name;

-- Prove an auditor CANNOT write (run this logged in as auditor1 - should FAIL):
--   INSERT INTO blocked_ips (ip_address, reason) VALUES ('1.2.3.4','test');
--   -- ERROR: permission denied for table blocked_ips

-- Prove an auditor CANNOT see password hashes (should FAIL):
--   SELECT password_hash FROM users LIMIT 1;
--   -- ERROR: permission denied for table users

-- NOTE: change every 'ChangeMe_...' password before submitting/using this
-- outside a local coursework environment.
