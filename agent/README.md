# NetSentinel Agent

The agent runs on **your machine** and performs all network scanning locally. There are no user accounts — the agent identifies itself with a generated installation ID.

## Install

Requires Python 3.10+.

```bash
cd agent
pip install -r requirements.txt
```

Optional but recommended: [install Nmap](https://nmap.org/download.html) for richer service/version detection. Without nmap the agent uses its built-in pure-Python scanner.

## Run

```bash
# Point the agent at your deployed API (Render)
export NETSENTINEL_API_URL=https://your-api.onrender.com
python main.py

# Or pass it directly
python main.py --api-url https://your-api.onrender.com

# Optional: force a specific installation ID
python main.py --id NS-7F42-A91C
```

First run output:

```
[INFO] NetSentinel Agent v1.0.0
[INFO] Installation ID: NS-7F42-A91C
[INFO] Registered with server.
[INFO] Agent registered. Waiting for scan jobs...
```

Keep the terminal open. The agent polls every 3 seconds for scan jobs and sends a heartbeat every 60 seconds.

## How identity works

- On first run the agent generates an installation ID (`NS-XXXX-XXXX`) and stores it in `~/.netsentinel/agent.json` together with the API-issued token.
- That ID is what the dashboard displays. It identifies the **installation**, not a person.
- Delete `~/.netsentinel/` to regenerate a fresh identity.

## What the agent does when a scan starts

1. Claims the pending scan from the API (pending → running)
2. Runs the pipeline locally:
   - Target validation
   - Host discovery (ICMP/ARP/TCP probes)
   - Port scanning (async TCP, or nmap when installed)
   - Service detection + banner grabbing
   - OS estimation (TTL heuristics)
   - CVE matching against a local curated feed
   - Risk engine → findings
3. Streams progress to the API (the dashboard polls it)
4. Submits full results; the scan flips to `completed`

## Safety

- Only scans targets you enter. The target validator rejects anything that isn't a plain IP/CIDR/hostname (no shell metacharacters, no option injection).
- Nmap runs via argv list with a `--` terminator, a flag whitelist and hard timeouts.
- Active checks are read-only (e.g., an `INFO` probe to Redis, `USER anonymous` to FTP).

## Scanning your own network only

By default there is no restriction on the target (it's your machine and your responsibility), but `validate_target` in the backend caps scans at 4096 hosts. Only scan networks you own or have permission to test.
