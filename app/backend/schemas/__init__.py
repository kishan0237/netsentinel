"""Pydantic schemas (request/response contracts) for the FastAPI backend."""

from datetime import datetime
from typing import Optional, Union
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

UUIDStr = Union[UUID, str]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------- agents ----
class AgentRegister(BaseModel):
    agent_uuid: str = Field(..., min_length=6, max_length=64, description="NS-XXXX-XXXX or raw UUID")
    agent_name: str = Field("NetSentinel Agent", max_length=255)
    hostname: Optional[str] = Field(None, max_length=255)
    platform: Optional[str] = Field(None, max_length=255)
    agent_version: str = Field("1.0.0", max_length=32)

    @field_validator("agent_uuid", "agent_name", "hostname", "platform", "agent_version")
    @classmethod
    def _strip(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if isinstance(v, str) else v


class AgentHeartbeat(BaseModel):
    agent_version: Optional[str] = Field(None, max_length=32)
    hostname: Optional[str] = Field(None, max_length=255)


class AgentOut(ORMModel):
    id: UUIDStr
    agent_uuid: str
    agent_name: str
    hostname: Optional[str] = None
    platform: Optional[str] = None
    agent_version: str
    status: str
    last_heartbeat: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


# ----------------------------------------------------------------- scans ----
class ScanCreate(BaseModel):
    agent_id: UUIDStr
    target: str = Field(..., min_length=1, max_length=255)
    scan_type: str = Field("standard", pattern="^(quick|standard|full|custom)$")
    ports: Optional[str] = Field(None, max_length=255, description="Custom range: '1-1000' or '22,80,443'")

    @field_validator("target", "ports")
    @classmethod
    def _strip(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if isinstance(v, str) else v


class ScanProgress(BaseModel):
    progress: int = Field(..., ge=0, le=100)
    current_stage: Optional[str] = Field(None, max_length=64)


class ScanOut(ORMModel):
    id: UUIDStr
    agent_id: Optional[UUIDStr] = None
    target: str
    scan_type: str
    ports: Optional[str] = None
    status: str
    progress: int
    current_stage: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


# ----------------------------------------------------------------- hosts ----
class HostOut(ORMModel):
    id: UUIDStr
    scan_id: UUIDStr
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    status: str
    os_estimate: Optional[str] = None
    created_at: datetime


# ----------------------------------------------------------------- ports ----
class PortOut(ORMModel):
    id: UUIDStr
    host_id: UUIDStr
    port_number: int
    protocol: str
    state: str
    created_at: datetime


# -------------------------------------------------------------- services ----
class ServiceOut(ORMModel):
    id: UUIDStr
    port_id: UUIDStr
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    created_at: datetime


# ------------------------------------------------------- vulnerabilities ----
class VulnerabilityOut(ORMModel):
    id: UUIDStr
    service_id: UUIDStr
    cve_id: str
    severity: str
    cvss_score: Optional[float] = None
    confidence: str
    description: Optional[str] = None
    solution: Optional[str] = None
    created_at: datetime


# -------------------------------------------------------------- findings ----
class FindingOut(ORMModel):
    id: UUIDStr
    scan_id: UUIDStr
    host_id: Optional[UUIDStr] = None
    service_id: Optional[UUIDStr] = None
    title: str
    description: Optional[str] = None
    severity: str
    recommendation: Optional[str] = None
    created_at: datetime


# --------------------------------------------------------------- reports ----
class ReportOut(ORMModel):
    id: UUIDStr
    scan_id: UUIDStr
    report_type: str
    file_path: Optional[str] = None
    created_at: datetime


# ------------------------------------------------------ nested scan tree ----
class VulnerabilityNested(VulnerabilityOut):
    pass


class ServiceNested(ServiceOut):
    vulnerabilities: list[VulnerabilityNested] = []


class PortNested(PortOut):
    services: list[ServiceNested] = []


class HostNested(HostOut):
    ports: list[PortNested] = []


class ScanResultsOut(ORMModel):
    scan: ScanOut
    hosts: list[HostNested] = []
    findings: list[FindingOut] = []


class ScanStats(BaseModel):
    hosts: int = 0
    open_ports: int = 0
    services: int = 0
    vulnerabilities: int = 0
    findings: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
