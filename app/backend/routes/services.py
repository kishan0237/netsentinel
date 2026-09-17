"""Service routes (read-only)."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Service
from app.backend.schemas import ServiceOut
from app.backend.utils.scan_authorization import coerce_uuid

router = APIRouter(prefix="/api/services", tags=["services"])


@router.get("", response_model=List[ServiceOut])
def list_services(
    port_id: str = Query(...),
    db: Session = Depends(get_db),
):
    from app.backend.database.models import Port

    try:
        port = db.get(Port, coerce_uuid(port_id))
    except ValueError:
        port = None
    if not port:
        raise HTTPException(404, "Port not found")
    services = db.query(Service).filter(Service.port_id == port.id).all()
    return [ServiceOut.model_validate(s).model_dump(mode="json") for s in services]
