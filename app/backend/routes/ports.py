"""Port routes (read-only)."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Port
from app.backend.schemas import PortOut
from app.backend.utils.scan_authorization import resolve_scan_or_404

router = APIRouter(prefix="/api/ports", tags=["ports"])


@router.get("", response_model=List[PortOut])
def list_ports(
    host_id: str = Query(...),
    limit: int = Query(1000, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    from app.backend.database.models import Host

    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    ports = (
        db.query(Port)
        .filter(Port.host_id == host_id)
        .order_by(Port.port_number)
        .limit(limit)
        .all()
    )
    return [PortOut.model_validate(p).model_dump(mode="json") for p in ports]
