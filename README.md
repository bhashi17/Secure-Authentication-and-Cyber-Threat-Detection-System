# Secure Authentication and Cyber Threat Detection System

Full PostgreSQL + PHP project covering Report Parts 1, 2 and 3.

## Folder structure
```
sql/
  01_schema.sql                        Part 1 - all 8 tables + base roles data
  02_seed_data.sql                     ~5,300 dummy rows (run after 01)
  03_indexing.sql                      Part 1 - 2 required indexes + before/after EXPLAIN ANALYZE
  04_procedures_functions_triggers.sql Part 2 - 2 procedures, 2 functions, 2 triggers
  05_roles_security.sql                Part 3 - 2 DB roles, 4 users each, privilege grants
php/
  config.php, index.php, users.php, user_form.php, login_attempts.php,
  security_logs.php, blocked_ips.php, audit_records.php, demo_procedures.php,
  includes/, assets/style.css
```

## 1. Set up the database
Requires PostgreSQL installed locally (or use pgAdmin's Query Tool for each file).

```bash
psql -U postgres -f sql/01_schema.sql
psql -U postgres -d secure_auth_system -f sql/02_seed_data.sql
psql -U postgres -d secure_auth_system -f sql/03_indexing.sql
psql -U postgres -d secure_auth_system -f sql/04_procedures_functions_triggers.sql
psql -U postgres -d secure_auth_system -f sql/05_roles_security.sql
psql -U postgres -d secure_auth_system -f sql/06_bulk_dummy_data.sql
```

Run them **in this order** - each file depends on the previous one (schema → data → indexes → logic → security → bulk volume).

### Fixed: "Security Logs" page showing 0 rows
`06_bulk_dummy_data.sql` previously targeted table names from an unrelated draft schema (`threat_logs` / `security_alerts` / `audit_logs`) that never matched `01_schema.sql`'s real tables (`threat_alerts` / `security_logs` / `audit_records`). That mismatch meant the bulk-load either errored out or silently inserted nothing, leaving `security_logs` (and friends) empty — the "1" you saw on the page was just the pagination control showing "page 1 of 1", not a log row. It's now rewritten to match the real schema and loads ~5,000 rows into `users`, `login_attempts`, `security_logs`, `blocked_ips`, `audit_records`, `sessions`, and `threat_alerts` (roles stays at 4 rows — it's a small reference table, not a log table, so it isn't a candidate for bulk volume). Run it once and the Security Logs page will populate immediately.

## 2. Set up the PHP UI
Requires PHP 8+ with the `pdo_pgsql` extension enabled.

```bash
cd php
php -S localhost:8000
```
Then open `http://localhost:8000/index.php`.

Before running, edit the 4 values at the top of `php/config.php` (host, port, db name, username/password) to match your local Postgres setup.

## 3. What's in the PHP UI
- **Dashboard** – live counts (users, failed logins, blocked IPs, critical logs, open alerts).
- **Users** – full CRUD (search, add, edit, delete).
- **Login Attempts** – view/filter/add/delete. Adding 5+ failed attempts from the same IP within 15 minutes fires `trg_flag_failed_login` automatically.
- **Security Logs** – view/filter/delete the events written by the procedures and triggers.
- **Blocked IPs** – view active/expired blocks, manually block/unblock/delete.
- **Audit Trail** – read-only view of everything written by `sp_deactivate_user` and `trg_audit_user_update`.
- **Viva Demo** – a single page that calls each of the 2 procedures and 2 functions directly with a button, so you can demonstrate each one individually to your examiner without navigating around.

## 4. For your report

**Part 1 (indexing):** run the BEFORE query in `03_indexing.sql`, screenshot the `EXPLAIN ANALYZE` output (shows `Seq Scan`), run the `CREATE INDEX` statement and screenshot it, then run the exact same query again and screenshot the AFTER output (shows `Index Scan` / `Bitmap Index Scan` with a lower cost/execution time). Do this for both required indexes (a 3rd optional partial index is also included).

**Part 2 (procedures/functions/triggers):** each block in `04_procedures_functions_triggers.sql` has a comment explaining what it does and why it's needed, plus a commented-out test query directly underneath it — run those and screenshot the results. The `demo_procedures.php` page is the easiest way to get clean screenshots of each one running through the UI.

**Part 3 (security):** `05_roles_security.sql` includes verification queries (commented at the bottom) to screenshot: the role list, the granted privileges, and a rejected write attempt from an `auditor` login proving the read-only restriction works.

**ERD / Use case diagram:** see the two diagrams shared in this conversation, which you can screenshot or recreate in draw.io/Lucidchart for the report.

## Notes
- Passwords in `05_roles_security.sql` are placeholders (`ChangeMe_...`) — change them before using this anywhere beyond local coursework.
- `password_hash` in the dummy data and PHP form uses MD5 purely as a stand-in; in a production system this must be a real password hash (bcrypt/Argon2), which the report can mention as a design note if asked.

## Login → Sign Up → Dashboard flow (fixed)

The auth flow has been wired up and locked down:
- `http://localhost:8000/index.php` — Login page (also the default page)
- `index.php` → link to `register.php` — Sign Up page
- After a successful login → redirect to `dashboard.php`
- `dashboard.php` and every other internal page (`users.php`, `login_attempts.php`, `security_logs.php`, `blocked_ips.php`, `audit_records.php`, `demo_procedures.php`, `user_form.php`) now `require 'includes/auth.php'`, which redirects anyone without a session back to the login page.
- If you're already logged in and visit `index.php`, you're bounced straight to `dashboard.php` instead of seeing the login form again.
- `logout.php` and `register.php` previously pointed at a `login.php` file that didn't exist — both now correctly point at `index.php`.
- The nav bar now shows the logged-in username and a Log Out link.
