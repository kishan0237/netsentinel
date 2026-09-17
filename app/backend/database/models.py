"""SQLAlchemy models for the 8-table NetSentinel schema.

IDs use SQLAlchemy's native Uuid type so they match supabase/migrations/
0001_init.sql exactly (native `uuid` columns on Postgres). This matters:
binding Python strings into a Postgres uuid column via psycopg3 fails with
"column is of type uuid but expression is of type text".
"""

import uuid as uuid_module
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.backend.database.database import Base

UuidPK = Uuid(as_uuid=True)


def _uuid() -> uuid_module.UUID:
    return uuid_module.uuid4()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    agent_uuid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False, default="NetSentinel Agent")
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    platform: Mapped[Optional[str]] = mapped_column(String(255))
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="offline")
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    scans: Mapped[list["Scan"]] = relationship(back_populates="agent")


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    agent_id: Mapped[Optional[uuid_module.UUID]] = mapped_column(
        UuidPK, ForeignKey("agents.id"), index=True
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(16), nullable=False, default="standard")
    ports: Mapped[Optional[str]] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_stage: Mapped[Optional[str]] = mapped_column(String(64))
    error: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    agent: Mapped[Optional[Agent]] = relationship(back_populates="scans")
    hosts: Mapped[list["Host"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("progress BETWEEN 0 AND 100", name="ck_scan_progress"),
        Index("idx_scans_created", "created_at"),
    )


class Host(Base, TimestampMixin):
    __tablename__ = "hosts"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    scan_id: Mapped[uuid_module.UUID] = mapped_column(
        UuidPK, ForeignKey("scans.id"), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[Optional[str]] = mapped_column(String(32))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="up")
    os_estimate: Mapped[Optional[str]] = mapped_column(String(255))

    scan: Mapped[Scan] = relationship(back_populates="hosts")
    ports: Mapped[list["Port"]] = relationship(back_populates="host", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("scan_id", "ip_address", name="uq_host_scan_ip"),)


class Port(Base, TimestampMixin):
    __tablename__ = "ports"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    host_id: Mapped[uuid_module.UUID] = mapped_column(
        UuidPK, ForeignKey("hosts.id"), nullable=False, index=True
    )
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)

    host: Mapped[Host] = relationship(back_populates="ports")
    services: Mapped[list["Service"]] = relationship(back_populates="port", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("port_number BETWEEN 0 AND 65535", name="ck_port_number"),
        UniqueConstraint("host_id", "port_number", "protocol", name="uq_port_host_num_proto"),
    )


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    port_id: Mapped[uuid_module.UUID] = mapped_column(
        UuidPK, ForeignKey("ports.id"), nullable=False, index=True
    )
    service_name: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[Optional[str]] = mapped_column(String(255))
    version: Mapped[Optional[str]] = mapped_column(String(64))
    banner: Mapped[Optional[str]] = mapped_column(Text)

    port: Mapped[Port] = relationship(back_populates="services")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="service", cascade="all, delete-orphan"
    )


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    service_id: Mapped[uuid_module.UUID] = mapped_column(
        UuidPK, ForeignKey("services.id"), nullable=False, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Numeric(3, 1))
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    description: Mapped[Optional[str]] = mapped_column(Text)
    solution: Mapped[Optional[str]] = mapped_column(Text)

    service: Mapped[Service] = relationship(back_populates="vulnerabilities")

    __table_args__ = (UniqueConstraint("service_id", "cve_id", name="uq_vuln_service_cve"),)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    scan_id: Mapped[uuid_module.UUID] = mapped_column(
        UuidPK, ForeignKey("scans.id"), nullable=False, index=True
    )
    host_id: Mapped[Optional[uuid_module.UUID]] = mapped_column(UuidPK, ForeignKey("hosts.id"))
    service_id: Mapped[Optional[uuid_module.UUID]] = mapped_column(UuidPK, ForeignKey("services.id"))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    recommendation: Mapped[Optional[str]] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[uuid_module.UUID] = mapped_column(UuidPK, primary_key=True, default=_uuid)
    scan_id: Mapped[uuid_module.UUID] = mapped_column(
        UuidPK, ForeignKey("scans.id"), nullable=False, index=True
    )
    report_type: Mapped[str] = mapped_column(String(16), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="reports")
