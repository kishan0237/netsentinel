"""Scan orchestration service.

Lifecycle: web dashboard creates a scan in `pending` state -> the agent
claims it via POST /api/scans/claim -> the agent runs the local pipeline,
streaming progress -> the agent pushes results -> scan becomes `completed`.
"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.backend.database.models import Agent, Finding, Host, Port, Report, Scan, Service, Vulnerability
from app.backend.schemas import ScanCreate
from app.backend.utils.input_validation import ValidationError, validate_ports_spec, validate_target
from app.backend.utils.scan_authorization import coerce_uuid
from app.backend.utils.secrets_management import redact_secrets

logger = logging.getLogger(__name__)

STAGES = ["target_validation", "host_discovery", "port_scanning", "service_detection",
          "os_fingerprint", "cve_enrichment", "risk_analysis", "reporting"]

MAX_HOSTS_PER_SCAN = 4096
MAX_FINDINGS_PER_SCAN = 500
MAX_PORTS_PER_HOST = 2000


class ScanValidationError(ValueError):
    pass


def create_scan(db: Session, payload: ScanCreate) -> Scan:
    """Validate and create a pending scan assigned to an agent."""
    try:
        target = validate_target(payload.target, max_hosts=MAX_HOSTS_PER_SCAN)
        ports = validate_ports_spec(payload.ports) if payload.scan_type == "custom" else None
    except ValidationError as e:
        raise ScanValidationError(str(e)) from e

    try:
        agent = db.get(Agent, coerce_uuid(payload.agent_id))
    except ValueError:
        agent = None
    if agent is None:
        raise ScanValidationError("Agent not found")

    scan = Scan(
        agent_id=agent.id,
        target=target,
        scan_type=payload.scan_type,
        ports=ports,
        status="pending",
        progress=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info("scan_created %s", redact_secrets({"scan_id": scan.id, "target": target}))
    return scan


STALE_SCAN_MINUTES = 30


def fail_stale_scans(db: Session, max_age_minutes: int = STALE_SCAN_MINUTES) -> int:
    """Mark scans stuck in running/pending as failed after the cutoff.

    Safety net for crashed agents or lost result submissions, so the
    dashboard never shows an eternally-running scan. Called opportunistically
    from read endpoints.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    stale = (
        db.query(Scan)
        .filter(Scan.status.in_(["running", "pending"]))
        .filter(Scan.created_at < cutoff)
        .all()
    )
    for scan in stale:
        scan.status = "failed"
        scan.error = "Scan abandoned: no result received (agent offline or submission lost)"
        scan.completed_at = datetime.now(timezone.utc)
        scan.progress = 100
    if stale:
        db.commit()
    return len(stale)


def claim_pending_scans(db: Session, agent: Agent, limit: int = 5) -> list[Scan]:
    """Atomically hand pending scans to an agent (status pending -> running)."""
    now = datetime.now(timezone.utc)
    pending = (
        db.query(Scan)
        .filter(Scan.agent_id == agent.id)
        .filter(Scan.status == "pending")
        .limit(limit)
        .all()
    )
    for scan in pending:
        scan.status = "running"
        scan.started_at = scan.started_at or now
        scan.progress = 0
        scan.current_stage = "starting"
    if pending:
        db.commit()
    return pending


def update_progress(db: Session, scan: Scan, progress: int, stage: Optional[str] = None) -> Scan:
    scan.progress = max(0, min(100, int(progress)))
    if stage:
        scan.current_stage = stage[:64]
    db.commit()
    db.refresh(scan)
    return scan


def fail_scan(db: Session, scan: Scan, error: str) -> Scan:
    scan.status = "failed"
    scan.error = error[:2000]
    scan.completed_at = datetime.now(timezone.utc)
    scan.progress = 100
    db.commit()
    db.refresh(scan)
    logger.warning("scan_failed %s", redact_secrets({"scan_id": scan.id, "error": error[:200]}))
    return scan


def cancel_scan(db: Session, scan: Scan) -> Scan:
    if scan.status in ("pending", "running"):
        scan.status = "cancelled"
        scan.completed_at = datetime.now(timezone.utc)
        scan.progress = 100
        db.commit()
        db.refresh(scan)
    return scan


def persist_results(
    db: Session,
    scan: Scan,
    results: dict[str, Any],
) -> dict[str, int]:
    """Persist a results payload from the agent and complete the scan.

    Expected shape (only include keys you have):
    {
      "hosts": [
        {
          "ip_address": "...", "mac_address": "...", "hostname": "...",
          "status": "up", "os_estimate": "...",
          "ports": [
            {"port_number": 22, "protocol": "tcp", "state": "open",
             "services": [
                {"service_name": "ssh", "product": "OpenSSH", "version": "8.4",
                 "banner": "...", "vulnerabilities": [{"cve_id": "...", ...}]}
             ]}
          ]
        }
      ],
      "findings": [ { "title": ..., "description": ..., "severity": ...,
                      "ip_address": "...", "recommendation": ... } ]
    }
    """
    now = datetime.now(timezone.utc)

    # Wipe any previous partial data for idempotent re-submission
    db.query(Finding).filter(Finding.scan_id == scan.id).delete()
    existing_host_ids = [h.id for h in db.query(Host).filter(Host.scan_id == scan.id).all()]
    db.query(Finding).filter(Finding.scan_id == scan.id).delete()
    if existing_host_ids:
        db.query(Host).filter(Host.id.in_(existing_host_ids)).delete(synchronize_session=False)
    db.query(Host).filter(Host.scan_id == scan.id).delete(synchronize_session=False)

    ip_to_host: dict[str, Host] = {}
    counts = {"hosts": 0, "ports": 0, "services": 0, "vulnerabilities": 0}

    for host_data in (results.get("hosts") or [])[:MAX_HOSTS_PER_SCAN]:
        if not isinstance(host_data, dict) or not host_data.get("ip_address"):
            continue
        host = Host(
            scan_id=scan.id,
            ip_address=str(host_data["ip_address"])[:45],
            mac_address=_clean(host_data.get("mac_address"), 32),
            hostname=_clean(host_data.get("hostname"), 255),
            status=_clean(host_data.get("status"), 16) or "up",
            os_estimate=_clean(host_data.get("os_estimate"), 255),
        )
        db.add(host)
        db.flush()
        ip_to_host[host.ip_address] = host
        counts["hosts"] += 1

        for port_data in (host_data.get("ports") or [])[:MAX_PORTS_PER_HOST]:
            try:
                port_number = int(port_data.get("port_number"))
            except (TypeError, ValueError):
                continue
            if not (0 <= port_number <= 65535):
                continue
            port = Port(
                host_id=host.id,
                port_number=port_number,
                protocol=_clean(port_data.get("protocol"), 8) or "tcp",
                state=_clean(port_data.get("state"), 16) or "open",
            )
            db.add(port)
            db.flush()
            counts["ports"] += 1

            for svc_data in (port_data.get("services") or []):
                service = Service(
                    port_id=port.id,
                    service_name=_clean(svc_data.get("service_name"), 64) or "unknown",
                    product=_clean(svc_data.get("product"), 255),
                    version=_clean(svc_data.get("version"), 64),
                    banner=_clean(svc_data.get("banner"), 10000),
                )
                db.add(service)
                db.flush()
                counts["services"] += 1

                for vuln_data in (svc_data.get("vulnerabilities") or [])[:50]:
                    cve_id = _clean(vuln_data.get("cve_id"), 32)
                    if not cve_id:
                        continue
                    vulnerability = Vulnerability(
                        service_id=service.id,
                        cve_id=cve_id,
                        severity=_clean(vuln_data.get("severity"), 16) or "medium",
                        cvss_score=_to_float(vuln_data.get("cvss_score")),
                        confidence=_clean(vuln_data.get("confidence"), 16) or "medium",
                        description=_clean(vuln_data.get("description"), None),
                        solution=_clean(vuln_data.get("solution"), None),
                    )
                    db.add(vulnerability)
                    counts["vulnerabilities"] += 1

    findings_added = 0
    for f_data in (results.get("findings") or [])[:MAX_FINDINGS_PER_SCAN]:
        if not isinstance(f_data, dict) or not f_data.get("title"):
            continue
        host_ref = ip_to_host.get(_clean(f_data.get("ip_address"), 45) or "")
        finding = Finding(
            scan_id=scan.id,
            host_id=host_ref.id if host_ref else None,
            title=_clean(f_data.get("title"), 255),
            description=_clean(f_data.get("description"), 10000),
            severity=_clean(f_data.get("severity"), 16) or "medium",
            recommendation=_clean(f_data.get("recommendation"), 10000),
        )
        db.add(finding)
        findings_added += 1

    scan.status = "completed"
    scan.progress = 100
    scan.current_stage = "done"
    scan.completed_at = now
    db.commit()

    logger.info(
        "scan_completed %s",
        redact_secrets({"scan_id": scan.id, **counts, "findings": findings_added}),
    )
    return {**counts, "findings": findings_added}


# PostgreSQL rejects NUL bytes in text values, and psycopg cannot encode
# lone surrogates; most other C0 control bytes are equally useless noise from
# binary protocol banners (MySQL handshakes, etc.). Scrub them once, at the
# single boundary every persisted result string passes through.
_DB_UNSAFE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")


def _clean(value: Any, max_len: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    s = _DB_UNSAFE_RE.sub("", str(value).strip())
    if not s:
        return None
    if max_len is not None:
        return s[:max_len]
    return s[:10000]


def _to_float(value: Any) -> Optional[float]:
    try:
        f = float(value)
        return f if 0.0 <= f <= 10.0 else None
    except (TypeError, ValueError):
        return None


def get_scan_results(db: Session, scan_id: str) -> dict[str, Any]:
    """Full nested results tree for the Results page."""
    try:
        scan = db.get(Scan, coerce_uuid(scan_id))
    except ValueError:
        scan = None
    if not scan:
        return {}

    hosts = (
        db.query(Host)
        .filter(Host.scan_id == scan.id)
        .order_by(Host.ip_address)
        .all()
    )
    host_ids = [h.id for h in hosts]

    ports = (
        db.query(Port).filter(Port.host_id.in_(host_ids)).order_by(Port.port_number).all()
        if host_ids else []
    )
    port_ids = [p.id for p in ports]

    services = (
        db.query(Service).filter(Service.port_id.in_(port_ids)).all()
        if port_ids else []
    )
    service_ids = [s.id for s in services]

    vulns = (
        db.query(Vulnerability).filter(Vulnerability.service_id.in_(service_ids)).all()
        if service_ids else []
    )

    ports_by_host: dict[str, list] = {}
    for p in ports:
        ports_by_host.setdefault(p.host_id, []).append(p)
    services_by_port: dict[str, list] = {}
    for s in services:
        services_by_port.setdefault(s.port_id, []).append(s)
    vulns_by_service: dict[str, list] = {}
    for v in vulns:
        vulns_by_service.setdefault(v.service_id, []).append(v)

    host_tree = []
    for h in hosts:
        ports_tree = []
        for p in ports_by_host.get(h.id, []):
            services_tree = []
            for s in services_by_port.get(p.id, []):
                services_tree.append(
                    {
                        **_orm_dict(s),
                        "vulnerabilities": [_orm_dict(v) for v in vulns_by_service.get(s.id, [])],
                    }
                )
            ports_tree.append({**_orm_dict(p), "services": services_tree})
        host_tree.append({**_orm_dict(h), "ports": ports_tree})

    findings = (
        db.query(Finding).filter(Finding.scan_id == scan.id).order_by(Finding.created_at).all()
    )

    return {
        "scan": _orm_dict(scan),
        "hosts": host_tree,
        "findings": [_orm_dict(f) for f in findings],
    }


def get_scan_stats(db: Session, scan: Scan) -> dict[str, Any]:
    """Aggregate stats for dashboard/summary views."""
    hosts = db.query(Host).filter(Host.scan_id == scan.id).all()
    host_ids = [h.id for h in hosts]
    ports = db.query(Port).filter(Port.host_id.in_(host_ids)).all() if host_ids else []
    port_ids = [p.id for p in ports]
    services = db.query(Service).filter(Service.port_id.in_(port_ids)).all() if port_ids else []
    service_ids = [s.id for s in services]
    vulns = db.query(Vulnerability).filter(Vulnerability.service_id.in_(service_ids)).all() if service_ids else []
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "hosts": len(hosts),
        "open_ports": sum(1 for p in ports if p.state == "open"),
        "services": len(services),
        "vulnerabilities": len(vulns),
        "findings": len(findings),
        "severity_counts": severity_counts,
    }


def create_report_record(db: Session, scan: Scan, report_type: str, file_path: Optional[str]) -> Report:
    report = Report(scan_id=scan.id, report_type=report_type, file_path=file_path)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def _orm_dict(obj: Any) -> dict:
    """Minimal from-orm serializer producing ISO timestamps and string UUIDs."""
    from app.backend.schemas import (
        FindingOut, HostOut, PortOut, ScanOut, ServiceOut, VulnerabilityOut,
    )

    if isinstance(obj, Scan):
        return ScanOut.model_validate(obj).model_dump(mode="json")
    if isinstance(obj, Host):
        return HostOut.model_validate(obj).model_dump(mode="json")
    if isinstance(obj, Port):
        return PortOut.model_validate(obj).model_dump(mode="json")
    if isinstance(obj, Service):
        return ServiceOut.model_validate(obj).model_dump(mode="json")
    if isinstance(obj, Vulnerability):
        return VulnerabilityOut.model_validate(obj).model_dump(mode="json")
    if isinstance(obj, Finding):
        return FindingOut.model_validate(obj).model_dump(mode="json")
    raise TypeError(f"Cannot serialize {type(obj)}")
