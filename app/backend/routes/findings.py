"""Finding routes (read-only)."""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Finding
from app.backend.schemas import FindingOut
from app.backend.utils.scan_authorization import resolve_scan_or_404

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=List[FindingOut])
def list_findings(
    scan_id: str = Query(...),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    scan = resolve_scan_or_404(db, scan_id)
    query = db.query(Finding).filter(Finding.scan_id == scan.id)
    if severity:
        query = query.filter(Finding.severity == severity.lower())
    findings = query.order_by(Finding.created_at).all()
    return [FindingOut.model_validate(f).model_dump(mode="json") for f in findings]
