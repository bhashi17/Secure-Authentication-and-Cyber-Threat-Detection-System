-- =====================================================================
-- 03_indexing.sql
-- Project Report Part 1 - Indexing
-- Run 01_schema.sql and 02_seed_data.sql first.
--
-- HOW TO USE FOR YOUR REPORT SCREENSHOTS:
--   1. Run the "BEFORE" EXPLAIN ANALYZE query and screenshot the output.
--   2. Run the CREATE INDEX statement and screenshot it.
--   3. Run the SAME EXPLAIN ANALYZE query again ("AFTER") and screenshot it.
--   Compare "Seq Scan" (before) vs "Index Scan"/"Bitmap Index Scan" (after)
--   and the drop in "execution time" / "cost".
-- =====================================================================


-- =====================================================================
-- INDEX 1
-- Description : Composite B-Tree index on login_attempts(ip_address, attempt_time)
-- Justification: The brute-force detection logic (and the sp_process_login_attempt
--   procedure / trigger) constantly runs queries of the form
--   "how many failed attempts came from this IP in the last N minutes".
--   Without an index, Postgres must sequentially scan the whole
--   login_attempts table (3,500+ rows and growing) for every single
--   login request, which does not scale. A composite index on
--   (ip_address, attempt_time) lets Postgres jump straight to the rows
--   for that IP and filter by time using the index alone.
-- =====================================================================

-- BEFORE (run this first, screenshot the plan - should show Seq Scan)
EXPLAIN ANALYZE
SELECT COUNT(*)
FROM login_attempts
WHERE ip_address = '185.220.101.5'
  AND is_success = FALSE
  AND attempt_time >= NOW() - INTERVAL '15 minutes';

-- INDEX IMPLEMENTATION
CREATE INDEX idx_login_attempts_ip_time
    ON login_attempts (ip_address, attempt_time);

-- AFTER (run the exact same query again - should show Index/Bitmap Scan)
EXPLAIN ANALYZE
SELECT COUNT(*)
FROM login_attempts
WHERE ip_address = '185.220.101.5'
  AND is_success = FALSE
  AND attempt_time >= NOW() - INTERVAL '15 minutes';


-- =====================================================================
-- INDEX 2
-- Description : Composite B-Tree index on security_logs(severity, event_type)
-- Justification: The security dashboard (PHP UI) filters logs by severity
--   (e.g. show all CRITICAL/HIGH events) and often further narrows by
--   event_type. This is a very frequent, user-facing, read-heavy query
--   pattern, so indexing the filtered columns avoids a full table scan
--   of security_logs every time an analyst opens the dashboard.
-- =====================================================================

-- BEFORE
EXPLAIN ANALYZE
SELECT log_id, event_type, severity, ip_address, created_at
FROM security_logs
WHERE severity = 'CRITICAL'
  AND event_type = 'SQL_INJECTION'
ORDER BY created_at DESC;

-- INDEX IMPLEMENTATION
CREATE INDEX idx_security_logs_severity_type
    ON security_logs (severity, event_type);

-- AFTER
EXPLAIN ANALYZE
SELECT log_id, event_type, severity, ip_address, created_at
FROM security_logs
WHERE severity = 'CRITICAL'
  AND event_type = 'SQL_INJECTION'
ORDER BY created_at DESC;


-- =====================================================================
-- INDEX 3 (bonus / optional - partial index)
-- Description : Partial B-Tree index on blocked_ips(ip_address) WHERE is_active = TRUE
-- Justification: Every incoming request must be checked against the
--   "is this IP currently blocked?" list. Only active blocks matter for
--   that check, so a partial index (indexing only is_active = TRUE rows)
--   is smaller and faster than indexing the whole table.
-- =====================================================================

-- BEFORE
EXPLAIN ANALYZE
SELECT 1 FROM blocked_ips WHERE ip_address = '91.240.118.3' AND is_active = TRUE;

-- INDEX IMPLEMENTATION
CREATE INDEX idx_blocked_ips_active
    ON blocked_ips (ip_address)
    WHERE is_active = TRUE;

-- AFTER
EXPLAIN ANALYZE
SELECT 1 FROM blocked_ips WHERE ip_address = '91.240.118.3' AND is_active = TRUE;
