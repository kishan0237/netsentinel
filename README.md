# NetSentinel

Agent-centric network scanner. **No user accounts, no logins, no passwords.**

## Live deployment

| Component | URL |
|---|---|
| Dashboard (Vercel) | https://netsentinel.vercel.app |
| API (Render) | https://netsentinel-api-utjb.onrender.com |
| API health | https://netsentinel-api-utjb.onrender.com/api/health |
| Swagger docs | https://netsentinel-api-utjb.onrender.com/docs |

Agent connects with `NETSENTINEL_API_URL=https://netsentinel-api-utjb.onrender.com`.
Dashboard builds need `VITE_API_URL` set to the Render URL (Vercel env var).

```
Vercel (dashboard)  ──HTTPS──▶  Render (FastAPI)  ──▶  Supabase (Postgres)
                                        ▲
                                        │ HTTPS (agent token)
                              Local Agent (your PC)
                                        │
                              Scanner pipeline (local network)
```

- **Vercel** — React/Vite dashboard. Read-only; polls the API.
- **Render** — FastAPI API. Coordinates agents and scan jobs, persists results.
- **Supabase** — PostgreSQL. 8 tables, RLS deny-all (only the backend's service connection touches data).
- **Agent** — Python. Runs on your machine, does all scanning, streams results.

## Deploy (15 minutes)

### 1. Supabase
1. Create a project at [supabase.com](https://supabase.com).
2. Open **SQL Editor**, paste the contents of [`supabase/migrations/0001_init.sql`](supabase/migrations/0001_init.sql), run it. (Optional — the backend also creates tables on startup.)
3. Copy the **connection string** (Project Settings → Database → URI). Use the **pooler** URI (port 6543).

### 2. Render
1. Push this repo to GitHub.
2. Render → **New → Blueprint** → select the repo (reads [`render.yaml`](render.yaml)). Or New → Web Service → Python, build `pip install -r requirements.txt`, start `uvicorn app.backend.main:app --host 0.0.0.0 --port $PORT`.
3. Set env vars (see [`.env.example`](.env.example)):
   - `DATABASE_URL` = your Supabase URI
   - `CORS_ORIGINS` = `https://<your-vercel-domain>,http://localhost:5173`
   - `ADMIN_API_KEY` = generate one
4. Verify: `https://<your-api>.onrender.com/api/health` → `{"status":"ok"}`. Swagger docs at `/docs`.

### 3. Vercel
1. Import the repo → root directory is the repo root (uses [`vercel.json`](vercel.json)).
2. Env var: `VITE_API_URL` = `https://<your-api>.onrender.com`.
3. Deploy.

### 4. Agent (your PC)
```bash
cd agent
pip install -r requests.txt 2>/dev/null || pip install -r requirements.txt
export NETSENTINEL_API_URL=https://<your-api>.onrender.com
python main.py
```
Keep it running. It registers as `NS-XXXX-XXXX` (stored in `~/.netsentinel/agent.json`) and waits for scan jobs. Details in [`agent/README.md`](agent/README.md). Optional: install [Nmap](https://nmap.org) for richer detection.

### 5. Scan
Open the dashboard → **New Scan** → target `192.168.1.0/24` → Standard → Start. The agent claims the job within ~3 seconds; watch live progress on the Results page.

## How it works

1. Dashboard `POST /api/scans` creates a **pending** scan assigned to your agent.
2. Agent `POST /api/scans/claim` picks it up (pending → running).
3. Agent runs the pipeline locally: target validation → host discovery (ICMP/ARP/TCP) → port scan (async TCP, or nmap if installed) → banner grab + service detection → OS estimate → CVE match → risk engine → findings.
4. Agent streams `POST /api/scans/{id}/progress` and submits `POST /api/scans/{id}/results`.
5. Dashboard polls `GET /api/scans/{id}` every 2s while running; results tree from `GET /api/scans/{id}/results`.

## API map

| Area | Endpoints |
|---|---|
| Agents | `POST /api/agents/register`, `POST /api/agents/heartbeat`, `GET /api/agents`, `GET /api/agents/{uuid}`, `DELETE /api/agents/{uuid}` (admin) |
| Scans | `POST /api/scans`, `POST /api/scans/claim`, `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/stats`, `GET /api/scans/{id}/results`, `POST /api/scans/{id}/progress`, `POST /api/scans/{id}/results`, `POST /api/scans/{id}/fail`, `POST /api/scans/{id}/cancel`, `GET /api/scans/{id}/report?format=html\|json\|csv` |
| Data | `GET /api/hosts?scan_id=`, `GET /api/ports?host_id=`, `GET /api/services?port_id=`, `GET /api/vulnerabilities?service_id=`, `GET /api/findings?scan_id=` |
| Reports | `POST /api/reports/generate/{scan_id}?report_type=`, `GET /api/reports`, `GET /api/reports/download/{report_id}` |
| Meta | `GET /api/health`, `GET /docs` (Swagger) |

Agent endpoints require `X-Agent-UUID` + `Authorization: Bearer <agent_token>` (issued at registration). Everything else is public read-only — matching the no-auth architecture.

## Database (8 tables, no users)

`agents · scans · hosts · ports · services · vulnerabilities · findings · reports`

Schema in [`supabase/migrations/0001_init.sql`](supabase/migrations/0001_init.sql). RLS is enabled with **no anon policies** (deny-all): the public key can't read or write anything; only the backend's service connection touches data.

## Local development

```bash
# Backend (terminal 1)
pip install -r requirements.txt
DATABASE_URL=sqlite:///./netsentinel.db uvicorn app.backend.main:app --reload

# Frontend (terminal 2)
npm install
VITE_API_URL=http://localhost:8000 npm run dev

# Agent (terminal 3)
cd agent && pip install -r requirements.txt
NETSENTINEL_API_URL=http://localhost:8000 python main.py

# Tests
python -m pytest          # 47 backend tests
npm run typecheck         # frontend types
npm run build             # frontend build
```

## Security notes

- No auth layer by design; agent tokens identify installations, not people.
- Scan targets are strictly validated (CIDR/IP/hostname only); shell metacharacters and nmap option injection are rejected.
- Nmap runs argv-list with `--` terminator, flag whitelist, timeouts and output caps.
- Rate limiting on scan creation, registration and heartbeats (tunable via env).
- Scan only networks you own or have permission to test.
