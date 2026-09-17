"""Scan routes: create from dashboard, agent claim/progress/results, reads."""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Agent, Scan
from app.backend.routes.deps import bearer_token, get_current_agent
from app.backend.schemas import (
    ScanCreate, ScanOut, ScanProgress, ScanResultsOut, ScanStats,
)
from app.backend.services import agent_service, report_service, scan_service
from app.backend.utils.rate_limiting import (
    general_limiter, get_client_ip, scan_create_limiter,
)
from app.backend.utils.scan_authorization import resolve_scan_or_404

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    request: Request,
    payload: ScanCreate,
    db: Session = Depends(get_db),
):
    """Create a scan (dashboard). The agent picks it up on its next poll."""
    scan_create_limiter.check(get_client_ip(request), "scan_create")
    try:
        scan = scan_service.create_scan(db, payload)
    except scan_service.ScanValidationError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    return ScanOut.model_validate(scan).model_dump(mode="json")


@router.post("/claim", response_model=List[ScanOut])
def claim_scans(
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Agent: claim pending scans assigned to it (pending -> running)."""
    claimed = scan_service.claim_pending_scans(db, agent)
    return [ScanOut.model_validate(s).model_dump(mode="json") for s in claimed]


@router.get("", response_model=List[ScanOut])
def list_scans(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    scan_service.fail_stale_scans(db)  # janitor: fail scans stuck >30 min
    scans = db.query(Scan)
    if status_filter:
        scans = scans.filter(Scan.status == status_filter)
    scans = scans.order_by(Scan.created_at.desc()).limit(limit).all()
    return [ScanOut.model_validate(s).model_dump(mode="json") for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    return ScanOut.model_validate(resolve_scan_or_404(db, scan_id)).model_dump(mode="json")


@router.get("/{scan_id}/stats", response_model=ScanStats)
def get_scan_stats(scan_id: str, db: Session = Depends(get_db)):
    scan = resolve_scan_or_404(db, scan_id)
    return scan_service.get_scan_stats(db, scan)


@router.get("/{scan_id}/results", response_model=ScanResultsOut)
def get_scan_results(scan_id: str, db: Session = Depends(get_db)):
    scan = resolve_scan_or_404(db, scan_id)
    results = scan_service.get_scan_results(db, scan.id)
    if not results:
        raise HTTPException(404, "Scan not found")
    return results


@router.post("/{scan_id}/progress", response_model=ScanOut)
def update_scan_progress(
    request: Request,
    scan_id: str,
    payload: ScanProgress,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Agent: stream pipeline progress for a scan it owns."""
    general_limiter.check(get_client_ip(request), "progress")
    scan = resolve_scan_or_404(db, scan_id)
    if scan.agent_id != agent.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Scan does not belong to this agent")
    return ScanOut.model_validate(
        scan_service.update_progress(db, scan, payload.progress, payload.current_stage)
    ).model_dump(mode="json")


@router.post("/{scan_id}/results", status_code=status.HTTP_201_CREATED)
def submit_scan_results(
    scan_id: str,
    payload: dict,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Agent: submit full scan results (hosts/ports/services/vulns/findings)."""
    scan = resolve_scan_or_404(db, scan_id)
    if scan.agent_id != agent.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Scan does not belong to this agent")
    counts = scan_service.persist_results(db, scan, payload)
    return {"status": "completed", "counts": counts}


@router.post("/{scan_id}/fail")
def fail_scan(
    scan_id: str,
    payload: dict,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Agent: report a scan failure with an error message."""
    scan = resolve_scan_or_404(db, scan_id)
    if scan.agent_id != agent.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Scan does not belong to this agent")
    scan_service.fail_scan(db, scan, str(payload.get("error", "Unknown error")))
    return {"status": "failed"}


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    """Cancel a pending/running scan (dashboard action)."""
    scan = resolve_scan_or_404(db, scan_id)
    return ScanOut.model_validate(scan_service.cancel_scan(db, scan)).model_dump(mode="json")


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    format: str = Query("html", pattern="^(html|json|csv)$"),
    db: Session = Depends(get_db),
):
    """Download the scan report directly (html/json/csv), generated on the fly."""
    scan = resolve_scan_or_404(db, scan_id)
    if scan.status != "completed":
        raise HTTPException(400, "Can only generate reports for completed scans")
    results = scan_service.get_scan_results(db, scan.id)
    content = report_service.generate_report(format, results)
    media = {"html": "text/html", "json": "application/json", "csv": "text/csv"}[format]
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="netsentinel-{str(scan.id)[:8]}.{format}"'},
    )
