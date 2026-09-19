# NetSentinel — Project Documentation

**Version 1.0.0** · FastAPI + React + Local Python Agent · No user accounts

NetSentinel is a network scanning platform with three cooperating parts: a public **web dashboard** (Vercel) for viewing results, a **REST API** (Render) that coordinates work and stores data, and a **local agent** that runs on the user's own PC and performs all actual network scanning. There is no login, registration, or user database anywhere in the system — an installation identifies itself with a generated agent ID and token instead.

---

## 1. Architecture

```
                    +---------------------+
                    |    Web Dashboard    |  React + Vite (static SPA)
                    |   Vercel hosting    |  public, read-only
                    +----------+----------+
                               | HTTPS (VITE_API_URL)
                               v
                    +---------------------+
                    |   FastAPI REST API  |  validation, coordination,
                    |   Render hosting    |  persistence, reports
                    +-----+---------+-----+
                          |         |
                PostgreSQL|         | REST (HTTPS)
              (Supabase)  v         v
                    +-----------+   +--------------------+
                    | Supabase  |   |   Local Agent      |  user's PC
                    | 8 tables  |   |  Python scanner    |
                    | RLS deny  |   |  heartbeats + poll |
                    +-----------+   +---------+----------+
                                              |
                                              v
                                       LOCAL NETWORK
                                  (hosts, ports, banners, CVEs)
```

Core principles:

- **No users.** No users table, no passwords, no JWT, no login/register pages. The dashboard is public read-only by design.
- **Agent identity, not user identity.** The agent generates an installation ID (`NS-XXXX-XXXX`) on first run and registers it with the API, which issues an installation token. All agent calls carry that identity.
- **Scanning never happens in the cloud.** The API only queues scan jobs; the agent executes them against the local network and uploads results.
- **One-way data flow for results:** agent -> API -> PostgreSQL -> dashboard (the dashboard polls every 2-3 seconds while a scan runs).

### Scan lifecycle

```
Dashboard                API (Render)                 Agent (user PC)
   |                         |                            |
   | POST /api/scans         |                            |
   |------------------------>|  status: pending           |
   |                         |                            |
   |                         |   POST /api/scans/claim    |
   |                         |<---------------------------|  (every 3 s)
   |                         |  status: running           |
   |                         |                            |
   | GET /results (poll)     |   POST /{id}/progress      |
   |------------------------>|<---------------------------|  5%..90% per stage
   |  live progress bar      |                            |
   |                         |   POST /{id}/results       |
   |                         |<---------------------------|  full payload
   |                         |  status: completed         |
   | GET /results            |                            |
   |------------------------>|                            |
   |  hosts/ports/CVEs       |                            |
```

---

## 2. Technology stack

| Layer         | Technology                                          |
|---------------|-----------------------------------------------------|
| Backend       | Python 3.11, FastAPI, SQLAlchemy 2, Pydantic v2     |
| Database      | PostgreSQL (Supabase), psycopg 3 driver             |
| Frontend      | React 18 + TypeScript, Vite, React Router           |
| Agent         | Python 3.10+, requests, asyncio-based TCP scanner   |
| Auxiliary     | nmap (optional, auto-detected for richer detection) |
| Hosting       | Vercel (dashboard), Render (API), Supabase (data)   |

---

## 3. Project structure

```
netsentinel/
|-- app/backend/                 FastAPI backend
|   |-- main.py                  app factory, CORS, /api/health, /api/version
|   |-- routes/                  agents, scans, hosts, ports, services,
|   |                            vulnerabilities, findings, reports
|   |-- schemas/                 Pydantic request/response models
|   |-- services/                scan_service, agent_service, cve_service,
|   |                            risk_service, report_service
|   |-- database/                engine/session, SQLAlchemy models
|   |-- utils/                   input_validation, rate_limiting,
|                                secrets_management, safe_nmap_execution,
|                                scan_authorization
|   +-- tests/                   48 pytest tests (API + validation + lifecycle)
|
|-- agent/                       local scanner agent
|   |-- main.py                  registration, poll loop, offline queue flush
|   |-- scanner/                 host_discovery, tcp/async/udp scanners,
|   |                            banner_grabber, service_detector,
|   |                            os_fingerprinter, nmap_engine, pipeline
|   |-- vulnerability/           cve_lookup, cve_matcher, active checks
|   |-- risk/                    risk_engine (CVSS banding, policy findings)
|   |-- reporting/               local html/json/csv reports
|   |-- communication/           api_client, heartbeat, reconnect, offline_queue
|   +-- security/                agent_identity, safe nmap execution
|
|-- src/                         React dashboard (Bolt-generated, REST-merged)
|   |-- lib/api.ts               typed REST client (single API boundary)
|   |-- hooks/                   useAgent, useScanPolling
|   +-- pages/                   Dashboard, Scan, Results, Reports, Docs...
|
|-- supabase/migrations/0001_init.sql    8-table schema + RLS deny-all
|-- scripts/smoke_test.py        end-to-end smoke test against a live API
|-- render.yaml                  Render blueprint
|-- vercel.json                  Vite build + SPA rewrites
|-- requirements.txt             backend dependencies
+-- .env.example                 all environment variables documented
```

---

## 4. Live deployment (current)

| Component | URL |
|---|---|
| REST API (Render) | `https://netsentinel-api-utjb.onrender.com` |
| API health | `https://netsentinel-api-utjb.onrender.com/api/health` |
| API docs (Swagger) | `https://netsentinel-api-utjb.onrender.com/docs` |
| API version/deploy marker | `https://netsentinel-api-utjb.onrender.com/api/version` |
| Dashboard (Vercel) | `https://netsentinel-ken-d179.vercel.app` |
| Database (Supabase) | Session pooler URI (stored as `DATABASE_URL` on Render only) |

Environment variables:

| Variable | Where | Purpose |
|---|---|---|
| `DATABASE_URL` | Render | Supabase Postgres URI (pooler, port 5432) |
| `CORS_ORIGINS` | Render | Comma list of allowed dashboard origins |
| `ADMIN_API_KEY` | Render | Shared secret for agent DELETE endpoint |
| `PYTHON_VERSION` | Render | Pinned `3.11.9` (wheels for all deps) |
| `AUTO_CREATE_TABLES` | Render | Idempotent `create_all()` on boot |
| `NVD_API_KEY` | Render | Optional live NVD CVE enrichment |
| `LOG_LEVEL` | Render | `INFO` (case-normalized in code) |
| `VITE_API_URL` | Vercel | Baked into the dashboard at build time |
| `NETSENTINEL_API_URL` | Agent PC | API base URL the agent talks to |
| `AGENT_POLL_INTERVAL` | Agent PC | Optional poll interval override (seconds) |

---

## 5. Local development setup

### 5.1 Backend

```bash
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r requirements.txt
set DATABASE_URL=sqlite:///./netsentinel.db        # or a Postgres URI
uvicorn app.backend.main:app --reload
# http://localhost:8000/api/health -> {"status":"ok","database":"ok"}
```

### 5.2 Frontend

```bash
npm install
set VITE_API_URL=http://localhost:8000
npm run dev      # http://localhost:5173
```

### 5.3 Agent

```bash
cd agent
pip install -r requirements.txt
set NETSENTINEL_API_URL=http://localhost:8000
python main.py
```

First run prints the generated installation ID and registers automatically. Identity is persisted to `%USERPROFILE%\.netsentinel\agent.json`; queued result files land in `%USERPROFILE%\.netsentinel\queue\`.

### 5.4 Tests and smoke test

```bash
python -m pytest                 # 48 tests
python scripts/smoke_test.py     # end-to-end: register -> scan -> results
```

---

## 6. API reference

Base URL: `https://netsentinel-api-utjb.onrender.com` (interactive docs at `/docs`).

Agent-authenticated endpoints require two headers:

```
X-Agent-UUID: NS-XXXX-XXXX
Authorization: Bearer <agent_token>
```

### 6.1 Meta

| Method | Path | Description |
|---|---|---|
| GET | `/` | Service descriptor |
| GET | `/api/health` | Liveness + database connectivity (`database: "ok"` or error text) |
| GET | `/api/version` | Running version + git commit (deploy verification) |

### 6.2 Agents

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/agents/register` | - | Register/update an installation; issues or rotates the agent token. Idempotent per `agent_uuid`. |
| POST | `/api/agents/heartbeat` | agent | Timestamped heartbeat; marks agent online. |
| GET | `/api/agents` | - | List agents with status/last heartbeat. |
| GET | `/api/agents/{agent_uuid}` | - | Single agent detail. |
| DELETE | `/api/agents/{agent_uuid}` | admin | Remove an agent (requires `X-Admin-Key: $ADMIN_API_KEY`). |

Registration request/response (abridged):

```json
POST /api/agents/register
{ "agent_uuid": "NS-28A7-CAFD", "hostname": "DESKTOP-ABC",
  "platform": "Windows 11", "agent_version": "1.0.0" }

201 { "agent": { "id": "...", "agent_uuid": "NS-28A7-CAFD", "status": "online", ... },
      "agent_token": "..." }
```

### 6.3 Scans

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/scans` | - | Create a pending scan. Body: `agent_id`, `target` (IP/CIDR), `scan_type` (`quick`/`standard`/`full`/`custom`), optional `ports` for custom. Strict validation rejects injection and malformed targets (422). |
| POST | `/api/scans/claim` | agent | Atomically hand pending scans to the calling agent (pending -> running). |
| GET | `/api/scans?status=&limit=` | - | List scans (newest first). Opportunistically fails scans stuck > 30 minutes. |
| GET | `/api/scans/{id}` | - | Single scan (status, progress, current_stage, error). |
| GET | `/api/scans/{id}/stats` | - | Aggregates: hosts, open_ports, services, vulnerabilities, findings, severity_counts. |
| GET | `/api/scans/{id}/results` | - | Full nested tree (hosts -> ports -> services -> vulnerabilities) + findings. Used by the Results page with 2 s polling. |
| POST | `/api/scans/{id}/progress` | agent | Stream progress (0-100) and stage name. Owner agent only. |
| POST | `/api/scans/{id}/results` | agent | Submit the full results payload; scan -> completed. Idempotent (re-submission wipes and replaces prior data). |
| POST | `/api/scans/{id}/fail` | agent | Report a failed scan with an error message. |
| POST | `/api/scans/{id}/cancel` | - | Cancel a pending/running scan. |
| GET | `/api/scans/{id}/report?format=html\|json\|csv` | - | Generate and download a report directly. |

Results payload shape (subset allowed — send only what you have):

```json
{
  "hosts": [
    { "ip_address": "192.168.1.10", "mac_address": "AA:BB:...", "hostname": "router.local",
      "status": "up", "os_estimate": "Linux 5.x",
      "ports": [
        { "port_number": 22, "protocol": "tcp", "state": "open",
          "services": [
            { "service_name": "ssh", "product": "OpenSSH", "version": "9.6",
              "banner": "SSH-2.0-OpenSSH_9.6",
              "vulnerabilities": [
                { "cve_id": "CVE-2024-6387", "severity": "critical", "cvss_score": 8.1,
                  "confidence": "medium", "description": "...", "solution": "..." } ] } ] } ] }
  ],
  "findings": [
    { "title": "CVE-2024-6387 on 192.168.1.10:22", "severity": "critical",
      "description": "...", "recommendation": "Upgrade OpenSSH",
      "ip_address": "192.168.1.10" } ]
}
```

Limits applied server-side: 4096 hosts, 2000 ports/host, 50 vulnerabilities/service, 500 findings/scan; all strings sanitized (control characters removed) before persistence.

### 6.4 Data reads

| Method | Path | Description |
|---|---|---|
| GET | `/api/hosts?scan_id=` | Hosts (optionally filtered by scan). |
| GET | `/api/hosts/{id}` | Host detail. |
| GET | `/api/ports` | Ports. |
| GET | `/api/services` | Detected services. |
| GET | `/api/vulnerabilities` | CVE matches. |
| GET | `/api/findings` | Risk-engine findings. |

### 6.5 Reports

| Method | Path | Description |
|---|---|---|
| POST | `/api/reports/generate/{scan_id}` | Persist a report record for a completed scan. |
| GET | `/api/reports` | List generated reports. |
| GET | `/api/reports/download/{report_id}` | Download a stored report. |

---

## 7. The agent

### 7.1 Identity

- First run generates `NS-XXXX-XXXX` (crypto RNG) and stores it with the issued token in `~/.netsentinel/agent.json`.
- Registration is idempotent: the same ID always updates the same row. A registration may rotate the token; the agent saves the new one.
- If any authenticated call is rejected (401/403) — e.g. token rotated elsewhere — the agent automatically re-registers and continues. The heartbeat thread signals this to the main loop.

### 7.2 Runtime loop

- Registers, then starts a 60 s heartbeat thread (keeps the dashboard status green and the free Render instance awake).
- Polls `POST /api/scans/claim` every 3 s for pending jobs.
- Runs the pipeline locally with per-stage progress callbacks streamed to the API.
- Submits results; on failure the payload is persisted to `~/.netsentinel/queue/<scan_id>.json` and re-submitted on every subsequent poll (with the *current* token — stale-token items are refreshed automatically).

### 7.3 Scanner pipeline

| Stage | What it does |
|---|---|
| `target_validation` | IP/CIDR validation, injection-safe, host-count cap |
| `host_discovery` | ICMP/ARP/TCP probes to find live hosts |
| `port_scanning` | Async TCP connect scan (+ thread-pool and UDP variants); auto-uses nmap when installed |
| `service_detection` | Protocol heuristics + banner classification |
| `os_fingerprint` | TTL/window-based estimate |
| `cve_enrichment` | Curated offline CVE feed; live NVD API when `NVD_API_KEY` set |
| `risk_analysis` | CVSS banding + policy checks (exposed Telnet/Redis/RDP, default creds, etc.) |
| `reporting` | Findings assembly; local HTML/JSON/CSV also saved by the agent |

Binary-protocol banners (e.g. MySQL handshakes) are stripped of NUL/control bytes at capture time, and the server sanitizes again at the persistence boundary — PostgreSQL rejects NULs in text columns.

---

## 8. Database schema (8 tables, Supabase PostgreSQL)

| Table | Key columns | Notes |
|---|---|---|
| `agents` | `id uuid PK`, `agent_uuid unique`, `status`, `last_heartbeat` | One row per installation |
| `scans` | `id uuid PK`, `agent_id FK`, `target`, `scan_type`, `status`, `progress`, `current_stage`, `error`, timestamps | Status: pending/running/completed/failed/cancelled |
| `hosts` | `id`, `scan_id FK`, `ip_address`, `mac_address`, `hostname`, `os_estimate` | |
| `ports` | `id`, `host_id FK`, `port_number`, `protocol`, `state` | Unique `(host_id, port_number, protocol)` |
| `services` | `id`, `port_id FK`, `service_name`, `product`, `version`, `banner` | |
| `vulnerabilities` | `id`, `service_id FK`, `cve_id`, `severity`, `cvss_score`, `confidence` | |
| `findings` | `id`, `scan_id FK`, `host_id FK nullable`, `title`, `severity`, `recommendation` | Risk-engine output |
| `reports` | `id`, `scan_id FK`, `report_type`, `file_path` | |

All IDs are native `uuid` columns with defaults; indexes exist on every foreign key and on hot filters (scan status, agent heartbeat, host IP). Row Level Security is enabled with a deny-all policy: only the backend's service connection (direct Postgres credentials) touches data; the Supabase anon key can read and write nothing.

---

## 9. Security model

| Concern | Mechanism |
|---|---|
| No user accounts | Entire auth layer removed by design; dashboard is public read-only |
| Agent authenticity | Per-installation bearer token issued at registration; `X-Agent-UUID` + token required on every agent route |
| Ownership | Agents can only progress/report on scans assigned to them (403 otherwise) |
| Admin actions | `DELETE /api/agents/{uuid}` gated by `ADMIN_API_KEY` |
| Target validation | Strict IP/CIDR grammar; rejects shell metacharacters and oversized ranges (tested against injection payloads) |
| Nmap execution | Argv-list only, flag whitelist, `--` terminator, per-run timeout, never shell interpolation |
| Rate limiting | Token-bucket per client IP on registration, heartbeat, scan creation, general traffic (env-tunable) |
| Input sanitation | All persisted strings stripped of control characters; lengths clamped to schema limits |
| Secrets | Only in platform env vars (Render); `.env` gitignored; agent token stored owner-only on disk |
| Data exposure | Supabase RLS deny-all; anon key useless even if leaked |

Known trade-off (accepted for this project's scope): anyone with the dashboard URL can read scan data. The natural next hardening step is a single shared secret on read routes.

---

## 10. Deployment guide

### 10.1 Supabase

1. Create a project; open SQL Editor and run `supabase/migrations/0001_init.sql`.
2. Settings -> Database -> Connection string -> **Session pooler** (URI, port 5432). Replace `[YOUR-PASSWORD]` with the real password. This URI is the Render `DATABASE_URL`.

### 10.2 Render (backend)

1. New -> Blueprint -> select the GitHub repo (reads `render.yaml`).
2. Fill the `sync: false` env vars: `DATABASE_URL`, `CORS_ORIGINS` (e.g. `https://your-app.vercel.app,http://localhost:5173`).
3. Deploy; verify `/api/health` returns `{"status":"ok","database":"ok"}` and `/api/version` shows the latest commit.

### 10.3 Vercel (dashboard)

1. Import the repo; framework preset **Vite**; root directory = repo root (do not deploy the `agent/` folder).
2. Add exactly one env var: `VITE_API_URL = https://netsentinel-api-utjb.onrender.com` (the `VITE_` prefix is required and intentionally public).
3. Redeploy after adding the variable — env vars are baked in at build time.
4. Verify the bundle: the built JS must contain the Render URL, not `localhost:8000`.

### 10.4 Agent (user PC)

```bat
cd agent
pip install -r requirements.txt
set NETSENTINEL_API_URL=https://netsentinel-api-utjb.onrender.com
python main.py
```

Expected log: installation ID, `Registered with server.`, `Agent registered. Waiting for scan jobs...`

---

## 11. Operations and troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/api/health` 500s or `database: error` | Bad `DATABASE_URL` (placeholder password, direct IPv6 URI instead of pooler) | Re-copy the Session pooler URI with the real password |
| Build fails on `pydantic-core` (Rust/maturin) | Python too new (3.14) for pinned wheels | Keep `PYTHON_VERSION=3.11.9` |
| `No module named 'psycopg2'` | Plain `postgresql://` URL maps to psycopg2 | Already handled: the engine rewrites the scheme to psycopg 3 |
| `Unknown level: 'info'` crash at boot | Lowercase `LOG_LEVEL` | Already handled: level is normalized in code |
| Agent registration returns 500 | Server older than commit `33b6925` (NUL-byte banner sanitizer) | Deploy latest commit; verify `/api/version` |
| Scan stuck at 90% | Result submission failed; results queued locally | Keep the agent running; it re-submits every poll with the current token |
| Scan stuck forever in running | Agent died mid-scan | Automatic janitor fails scans after 30 min |
| Dashboard shows agent offline | Agent window closed, or token rotated before the hardening commit | Restart the agent (auto re-registration is built in now) |
| Dashboard calls fail in browser (CORS) | Vercel origin not in `CORS_ORIGINS` | Add `https://<domain>.vercel.app` on Render |
| Bundle points at `localhost:8000` | `VITE_API_URL` missing at build time | Add it in Vercel, then Redeploy |
| Render never deploys new pushes | Auto-deploy off or dead GitHub webhook | Events tab -> Manual Deploy -> "Deploy latest commit"; re-check Auto-Deploy settings |

Free-tier notes: Render sleeps the API after ~15 idle minutes, but a running agent's 60 s heartbeat keeps it warm. Scans created while the agent is offline run on reconnect. The offline queue is durable — closing the agent mid-scan loses nothing.

---

## 12. Verification summary

- 48 backend tests: registration, scan lifecycle, ownership/authorization, input-injection rejection, UUID handling, binary-banner regression, report generation.
- End-to-end smoke test (`scripts/smoke_test.py`): register -> create -> claim -> live pipeline -> results -> report, run against a real server.
- Production verification performed on the live deployment: health with database check, agent online via heartbeat, real LAN scan persisted through Supabase and rendered on the dashboard.
