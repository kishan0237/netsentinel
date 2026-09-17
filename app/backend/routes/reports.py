"""Report routes: generate HTML/JSON/CSV reports for completed scans."""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.backend.database.database import get_db
from app.backend.database.models import Report
from app.backend.schemas import ReportOut
from app.backend.services import report_service, scan_service
from app.backend.utils.scan_authorization import coerce_uuid, resolve_scan_or_404

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])

MEDIA_TYPES = {"html": "text/html", "json": "application/json", "csv": "text/csv"}


@router.post("/generate/{scan_id}", response_model=ReportOut, status_code=201)
def generate_report(scan_id: str, report_type: str = "html", db: Session = Depends(get_db)):
    """Generate a report for a completed scan and record it."""
    scan = resolve_scan_or_404(db, scan_id)
    if scan.status != "completed":
        raise HTTPException(400, "Can only generate reports for completed scans")
    if report_type not in ("html", "json", "csv"):
        raise HTTPException(422, "report_type must be html, json or csv")

    results = scan_service.get_scan_results(db, scan.id)
    file_path = f"/reports/{scan.id}.{report_type}"
    report = scan_service.create_report_record(db, scan, report_type, file_path)
    logger.info("report_generated %s %s", scan.id, report_type)
    return ReportOut.model_validate(report).model_dump(mode="json")


@router.get("", response_model=List[ReportOut])
def list_reports(limit: int = 100, db: Session = Depends(get_db)):
    reports = db.query(Report).order_by(Report.created_at.desc()).limit(limit).all()
    return [ReportOut.model_validate(r).model_dump(mode="json") for r in reports]


@router.get("/download/{report_id}")
def download_report(report_id: str, db: Session = Depends(get_db)):
    """Regenerate the report content on the fly and stream it as a file."""
    try:
        report = db.get(Report, coerce_uuid(report_id))
    except ValueError:
        report = None
    if not report:
        raise HTTPException(404, "Report not found")
    scan = resolve_scan_or_404(db, report.scan_id)
    results = scan_service.get_scan_results(db, scan.id)
    try:
        content = report_service.generate_report(report.report_type, results)
    except ValueError:
        raise HTTPException(422, f"Unsupported report type: {report.report_type}")

    ext = report.report_type
    return Response(
        content=content,
        media_type=MEDIA_TYPES.get(ext, "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="netsentinel-{scan.target.replace("/", "_")}-{ext}.{ext}"'
        },
    )
