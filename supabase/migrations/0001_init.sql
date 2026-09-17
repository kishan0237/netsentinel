-- NetSentinel v1 schema — 8 tables, no users/auth layer.
-- Run this in the Supabase SQL editor (or via `supabase db push`).
--
-- Security model: all writes go through the FastAPI backend on Render using
-- the service-role key. Row Level Security is enabled with NO anon policies
-- (deny-all), so the public anon key can never read or write data directly.
-- There is no users table, no passwords, no JWT, no login/register.

create extension if not exists "pgcrypto";

-- 1. agents -----------------------------------------------------------------
create table if not exists agents (
  id             uuid primary key default gen_random_uuid(),
  agent_uuid     text not null unique,
  agent_name     text not null default 'NetSentinel Agent',
  hostname       text,
  platform       text,
  agent_version  text not null default '1.0.0',
  status         text not null default 'offline'
                 check (status in ('online', 'offline', 'unknown')),
  last_heartbeat timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

-- 2. scans ------------------------------------------------------------------
create table if not exists scans (
  id            uuid primary key default gen_random_uuid(),
  agent_id      uuid references agents(id) on delete set null,
  target        text not null,
  scan_type     text not null
                check (scan_type in ('quick', 'standard', 'full', 'custom')),
  ports         text,
  status        text not null default 'pending'
                check (status in ('pending', 'running', 'completed', 'failed', 'cancelled')),
  progress      integer not null default 0 check (progress between 0 and 100),
  current_stage text,
  error         text,
  started_at    timestamptz,
  completed_at  timestamptz,
  created_at    timestamptz not null default now()
);

-- 3. hosts ------------------------------------------------------------------
create table if not exists hosts (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references scans(id) on delete cascade,
  ip_address  text not null,
  mac_address text,
  hostname    text,
  status      text not null default 'up' check (status in ('up', 'down')),
  os_estimate text,
  created_at  timestamptz not null default now(),
  unique (scan_id, ip_address)
);

-- 4. ports ------------------------------------------------------------------
create table if not exists ports (
  id          uuid primary key default gen_random_uuid(),
  host_id     uuid not null references hosts(id) on delete cascade,
  port_number integer not null check (port_number between 0 and 65535),
  protocol    text not null default 'tcp' check (protocol in ('tcp', 'udp')),
  state       text not null default 'open' check (state in ('open', 'closed', 'filtered')),
  created_at  timestamptz not null default now(),
  unique (host_id, port_number, protocol)
);

-- 5. services ---------------------------------------------------------------
create table if not exists services (
  id           uuid primary key default gen_random_uuid(),
  port_id      uuid not null references ports(id) on delete cascade,
  service_name text not null,
  product      text,
  version      text,
  banner       text,
  created_at   timestamptz not null default now()
);

-- 6. vulnerabilities --------------------------------------------------------
create table if not exists vulnerabilities (
  id          uuid primary key default gen_random_uuid(),
  service_id  uuid not null references services(id) on delete cascade,
  cve_id      text not null,
  severity    text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  cvss_score  numeric(3, 1),
  confidence  text not null default 'medium' check (confidence in ('high', 'medium', 'low')),
  description text,
  solution    text,
  created_at  timestamptz not null default now(),
  unique (service_id, cve_id)
);

-- 7. findings ---------------------------------------------------------------
create table if not exists findings (
  id             uuid primary key default gen_random_uuid(),
  scan_id        uuid not null references scans(id) on delete cascade,
  host_id        uuid references hosts(id) on delete cascade,
  service_id     uuid references services(id) on delete cascade,
  title          text not null,
  description    text,
  severity       text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  recommendation text,
  created_at     timestamptz not null default now()
);

-- 8. reports ----------------------------------------------------------------
create table if not exists reports (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references scans(id) on delete cascade,
  report_type text not null check (report_type in ('html', 'json', 'csv')),
  file_path   text,
  created_at  timestamptz not null default now()
);

-- Indexes ---------------------------------------------------------------------
create index if not exists idx_agents_status       on agents (status);
create index if not exists idx_scans_agent         on scans (agent_id);
create index if not exists idx_scans_status        on scans (status);
create index if not exists idx_scans_created       on scans (created_at desc);
create index if not exists idx_hosts_scan          on hosts (scan_id);
create index if not exists idx_ports_host          on ports (host_id);
create index if not exists idx_ports_state         on ports (state);
create index if not exists idx_services_port       on services (port_id);
create index if not exists idx_vulns_service       on vulnerabilities (service_id);
create index if not exists idx_vulns_cve           on vulnerabilities (cve_id);
create index if not exists idx_findings_scan       on findings (scan_id);
create index if not exists idx_findings_severity   on findings (severity);
create index if not exists idx_reports_scan        on reports (scan_id);

-- Row Level Security: deny-all for anon/authenticated keys --------------------
-- The FastAPI backend connects with the service_role key, which bypasses RLS.
alter table agents          enable row level security;
alter table scans           enable row level security;
alter table hosts           enable row level security;
alter table ports           enable row level security;
alter table services        enable row level security;
alter table vulnerabilities enable row level security;
alter table findings        enable row level security;
alter table reports         enable row level security;
