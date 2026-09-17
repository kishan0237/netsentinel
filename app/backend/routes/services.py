"""Service routes (read-only)."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Service
from app.backend.schemas import ServiceOut

router = APIRouter(prefix="/api/services", tags=["services"])


@router.get("", response_model=List[ServiceOut])
def list_services(
    port_id: str = Query(...),
    db: Session = Depends(get_db),
):
    from app.backend.database.models import Port

    port = db.get(Port, port_id)
    if not port:
        raise HTTPException(404, "Port not found")
    services = db.query(Service).filter(Service.port_id == port_id).all()
    return [ServiceOut.model_validate(s).model_dump(mode="json") for s in services]
