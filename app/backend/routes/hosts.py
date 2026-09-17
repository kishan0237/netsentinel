"""Host routes (read-only)."""

from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Host
from app.backend.schemas import HostOut
from app.backend.utils.scan_authorization import coerce_uuid, resolve_scan_or_404

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("", response_model=List[HostOut])
def list_hosts(
    scan_id: str = Query(...),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    scan = resolve_scan_or_404(db, scan_id)
    hosts = (
        db.query(Host)
        .filter(Host.scan_id == scan.id)
        .order_by(Host.ip_address)
        .limit(limit)
        .all()
    )
    return [HostOut.model_validate(h).model_dump(mode="json") for h in hosts]


@router.get("/{host_id}", response_model=HostOut)
def get_host(host_id: str, db: Session = Depends(get_db)):
    try:
        host = db.get(Host, coerce_uuid(host_id))
    except ValueError:
        host = None
    if not host:
        from fastapi import HTTPException
        raise HTTPException(404, "Host not found")
    return HostOut.model_validate(host).model_dump(mode="json")
