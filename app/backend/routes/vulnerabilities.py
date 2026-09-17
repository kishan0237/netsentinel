"""Vulnerability routes (read-only)."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Vulnerability
from app.backend.schemas import VulnerabilityOut

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=List[VulnerabilityOut])
def list_vulnerabilities(
    service_id: str = Query(...),
    db: Session = Depends(get_db),
):
    from app.backend.database.models import Service

    service = db.get(Service, service_id)
    if not service:
        raise HTTPException(404, "Service not found")
    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.service_id == service_id)
        .order_by(Vulnerability.cvss_score.desc())
        .all()
    )
    return [VulnerabilityOut.model_validate(v).model_dump(mode="json") for v in vulns]
