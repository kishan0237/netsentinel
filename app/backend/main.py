"""NetSentinel FastAPI backend — agent-centric network scanner API.

No user auth: the dashboard is public read-only; agents authenticate with an
installation token issued at registration.
"""

import logging
import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.backend.database.database import get_db

from app.backend.database.database import init_db
from app.backend.routes import (
    agents, findings, hosts, ports, reports, scans, services, vulnerabilities,
)
from app.backend.utils.secrets_management import generate_installation_id  # noqa: F401

log_level = (os.getenv("LOG_LEVEL") or "INFO").strip().upper()
if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
    log_level = "INFO"
logging.basicConfig(level=log_level)
logger = logging.getLogger("netsentinel")

app = FastAPI(
    title="NetSentinel API",
    version="1.0.0",
    description="Agent-centric network scanning API (no user auth layer).",
    docs_url="/docs",
    openapi_url="/openapi.json",
)

DEFAULT_ORIGINS = "http://localhost:5173,http://localhost:4173,http://localhost:3000"
ALLOWED_ORIGINS = [
    o.strip() for o in (os.getenv("CORS_ORIGINS") or DEFAULT_ORIGINS).split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=os.getenv("CORS_ORIGIN_REGEX", r"https://.*\.vercel\.app"),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    logger.info("NetSentinel API started (CORS origins: %s)", ALLOWED_ORIGINS)


app.include_router(agents.router)
app.include_router(scans.router)
app.include_router(hosts.router)
app.include_router(ports.router)
app.include_router(services.router)
app.include_router(vulnerabilities.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/", tags=["meta"])
def root():
    return {"name": "NetSentinel API", "version": "1.0.0", "docs": "/docs"}


@app.get("/api/version", tags=["meta"])
def version():
    """Deploy marker: which commit is actually running (Render injects it)."""
    return {
        "version": "1.0.0",
        "git_commit": (os.getenv("RENDER_GIT_COMMIT") or "unknown")[:7],
    }


@app.get("/api/health", tags=["meta"])
def health(db=Depends(get_db)):
    """Liveness + database connectivity check.

    `database` is "ok" or a short error string, so deployment issues
    (wrong password, unreachable host) are visible in one request.
    """
    from sqlalchemy import text

    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:  # noqa: BLE001 — diagnostics must never 500
        database = f"error: {str(e)[:300]}"
        logger.error("Database health check failed: %s", e)
    return {"status": "ok", "database": database}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
