/*
# NetSentinel Schema — Agent-Centric Network Scanner

This migration creates the complete database schema for NetSentinel, an agent-centric
network scanning platform. There is NO user authentication system — the app identifies
installations via agent tokens, not user accounts.

## Tables Created (8 total)

1. **agents** — Represents a NetSentinel agent installation. Identified by a unique
   agent_uuid (e.g., NS-7F42-A91C). Tracks status, heartbeat, platform info.
2. **scans** — Network scans initiated by an agent. Tracks target, scan type, status,
   progress, and timestamps.
3. **hosts** — Discovered hosts during a scan. IP, MAC, hostname, status, OS estimate.
4. **ports** — Open/closed ports on a discovered host. Port number, protocol, state.
5. **services** — Services detected on a port. Service name, product, version.
6. **vulnerabilities** — CVEs matched to detected services. Severity, CVSS, description,
   solution.
7. **findings** — Risk-engine findings aggregating vulnerabilities per scan/host/service.
   Title, description, severity, recommendation.
8. **reports** — Generated scan reports. Report type, file path, creation timestamp.

## Security

- RLS enabled on ALL tables.
- This is a no-auth single-tenant app: all policies use `TO anon, authenticated` with
  `USING (true)` / `WITH CHECK (true)` because the data is intentionally shared/public
  (no user accounts exist in this architecture).
- No user_id columns, no auth.uid() checks, no JWT tokens.

## Important Notes

1. All foreign keys use ON DELETE CASCADE to maintain referential integrity.
2. Timestamps default to now() for created_at and updated_at.
3. Agent UUIDs follow the format NS-XXXX-XXXX (human-readable installation ID).
4. Scan types: quick, standard, full, custom.
5. Scan status: pending, running, completed, failed.
6. Host status: up, down.
7. Port state: open, closed, filtered.
8. Vulnerability severity: critical, high, medium, low, info.
*/

-- ============================================================
-- 1. AGENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_uuid text UNIQUE NOT NULL,
  agent_name text NOT NULL DEFAULT 'NetSentinel Agent',
  hostname text,
  platform text,
  agent_version text NOT NULL DEFAULT '1.0.0',
  status text NOT NULL DEFAULT 'offline',
  last_heartbeat timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_agents" ON agents;
CREATE POLICY "anon_select_agents" ON agents FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_agents" ON agents;
CREATE POLICY "anon_insert_agents" ON agents FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_agents" ON agents;
CREATE POLICY "anon_update_agents" ON agents FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_agents" ON agents;
CREATE POLICY "anon_delete_agents" ON agents FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- 2. SCANS
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid REFERENCES agents(id) ON DELETE CASCADE,
  target text NOT NULL,
  scan_type text NOT NULL DEFAULT 'standard',
  status text NOT NULL DEFAULT 'pending',
  progress integer NOT NULL DEFAULT 0,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_scans" ON scans;
CREATE POLICY "anon_select_scans" ON scans FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_scans" ON scans;
CREATE POLICY "anon_insert_scans" ON scans FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_scans" ON scans;
CREATE POLICY "anon_update_scans" ON scans FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_scans" ON scans;
CREATE POLICY "anon_delete_scans" ON scans FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- 3. HOSTS
-- ============================================================
CREATE TABLE IF NOT EXISTS hosts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
  ip_address text NOT NULL,
  mac_address text,
  hostname text,
  status text NOT NULL DEFAULT 'up',
  os_estimate text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE hosts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_hosts" ON hosts;
CREATE POLICY "anon_select_hosts" ON hosts FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_hosts" ON hosts;
CREATE POLICY "anon_insert_hosts" ON hosts FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_hosts" ON hosts;
CREATE POLICY "anon_update_hosts" ON hosts FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_hosts" ON hosts;
CREATE POLICY "anon_delete_hosts" ON hosts FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- 4. PORTS
-- ============================================================
CREATE TABLE IF NOT EXISTS ports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id uuid REFERENCES hosts(id) ON DELETE CASCADE NOT NULL,
  port_number integer NOT NULL,
  protocol text NOT NULL DEFAULT 'tcp',
  state text NOT NULL DEFAULT 'open',
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE ports ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_ports" ON ports;
CREATE POLICY "anon_select_ports" ON ports FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_ports" ON ports;
CREATE POLICY "anon_insert_ports" ON ports FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_ports" ON ports;
CREATE POLICY "anon_update_ports" ON ports FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_ports" ON ports;
CREATE POLICY "anon_delete_ports" ON ports FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- 5. SERVICES
-- ============================================================
CREATE TABLE IF NOT EXISTS services (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  port_id uuid REFERENCES ports(id) ON DELETE CASCADE NOT NULL,
  service_name text NOT NULL,
  product text,
  version text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE services ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_services" ON services;
CREATE POLICY "anon_select_services" ON services FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_services" ON services;
CREATE POLICY "anon_insert_services" ON services FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_services" ON services;
CREATE POLICY "anon_update_services" ON services FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_services" ON services;
CREATE POLICY "anon_delete_services" ON services FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- 6. VULNERABILITIES
-- ============================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_id uuid REFERENCES services(id) ON DELETE CASCADE NOT NULL,
  cve_id text NOT NULL,
  severity text NOT NULL DEFAULT 'medium',
  cvss_score numeric DEFAULT 0,
  confidence text NOT NULL DEFAULT 'medium',
  description text,
  solution text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_vulnerabilities" ON vulnerabilities;
CREATE POLICY "anon_select_vulnerabilities" ON vulnerabilities FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_vulnerabilities" ON vulnerabilities;
CREATE POLICY "anon_insert_vulnerabilities" ON vulnerabilities FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_vulnerabilities" ON vulnerabilities;
CREATE POLICY "anon_update_vulnerabilities" ON vulnerabilities FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_vulnerabilities" ON vulnerabilities;
CREATE POLICY "anon_delete_vulnerabilities" ON vulnerabilities FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- 7. FINDINGS
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
  host_id uuid REFERENCES hosts(id) ON DELETE CASCADE,
  service_id uuid REFERENCES services(id) ON DELETE CASCADE,
  title text NOT NULL,
  description text,
  severity text NOT NULL DEFAULT 'medium',
  recommendation text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_findings" ON findings;
CREATE POLICY "anon_select_findings" ON findings FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_findings" ON findings;
CREATE POLICY "anon_insert_findings" ON findings FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_findings" ON findings;
CREATE POLICY "anon_update_findings" ON findings FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_findings" ON findings;
CREATE POLICY "anon_delete_findings" ON findings FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- 8. REPORTS
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
  report_type text NOT NULL DEFAULT 'html',
  file_path text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_reports" ON reports;
CREATE POLICY "anon_select_reports" ON reports FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_reports" ON reports;
CREATE POLICY "anon_insert_reports" ON reports FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_reports" ON reports;
CREATE POLICY "anon_update_reports" ON reports FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_reports" ON reports;
CREATE POLICY "anon_delete_reports" ON reports FOR DELETE
  TO anon, authenticated USING (true);

-- ============================================================
-- INDEXES for performance
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_scans_agent_id ON scans(agent_id);
CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_services_port_id ON services(port_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_service_id ON vulnerabilities(service_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);