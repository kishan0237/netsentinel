"""Input validation for scan targets and custom port specs.

Security-critical: the API must reject anything that is not a plain network
target so it can never be interpreted as a shell argument by nmap or the
agent. Nmap will run with `--` argument-injection protection on the agent.
"""

import ipaddress
import re
import socket
from typing import Optional

MAX_HOSTS_DEFAULT = 4096

_CDIR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")


class ValidationError(ValueError):
    """Raised when a target or port spec is invalid."""


def validate_target(target: str, max_hosts: int = MAX_HOSTS_DEFAULT) -> str:
    """Validate and normalize a scan target.

    Accepts: single IP, CIDR range, hostname, or comma-separated list of those.
    Rejects: anything containing characters that could enable option injection.
    Returns the normalized target string.
    """
    if not target or not isinstance(target, str):
        raise ValidationError("Target is required")

    cleaned = target.strip()
    if not cleaned or len(cleaned) > 255:
        raise ValidationError("Target must be 1-255 characters")

    # Hard-deny characters that have no business in a scan target.
    if re.search(r"[;&|`$<>\\'\"]", cleaned):
        raise ValidationError("Target contains forbidden characters")

    parts = [p.strip() for p in cleaned.split(",") if p.strip()]
    if not parts:
        raise ValidationError("Target is required")
    if len(parts) > 8:
        raise ValidationError("Maximum 8 comma-separated targets")

    total_hosts = 0
    for part in parts:
        _validate_single_target(part, max_hosts_per_target=1)
        total_hosts += _estimate_host_count(part)
        if total_hosts > max_hosts:
            raise ValidationError(f"Target exceeds maximum of {max_hosts} hosts")

    return ",".join(parts)


def _validate_single_target(part: str, max_hosts_per_target: int) -> None:
    # CIDR like 192.168.1.0/24
    if "/" in part:
        if not _CDIR_RE.match(part):
            raise ValidationError(f"Invalid CIDR notation: {part}")
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR notation: {part}") from e
        if net.num_addresses > max_hosts_per_target * MAX_HOSTS_DEFAULT:
            raise ValidationError(f"CIDR too large: {part}")
        return

    # Single IP
    try:
        ipaddress.ip_address(part)
        return
    except ValueError:
        pass

    # Hostname (also resolves? no - just validate syntax; resolution is agent-side)
    if not re.match(
        r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$",
        part,
    ):
        raise ValidationError(f"Invalid target: {part}")


def _estimate_host_count(part: str) -> int:
    if "/" in part:
        try:
            return ipaddress.ip_network(part, strict=False).num_addresses
        except ValueError:
            return 1
    return 1


def validate_ports_spec(spec: Optional[str]) -> Optional[str]:
    """Validate a custom port spec like '1-1000' or '22,80,443'.

    Returns the cleaned spec, or None if empty. Raises ValidationError on
    anything malformed, out of range, or excessively large.
    """
    if spec is None or (isinstance(spec, str) and not spec.strip()):
        return None

    cleaned = spec.strip()
    if len(cleaned) > 255:
        raise ValidationError("Port spec too long")

    if not re.fullmatch(r"[0-9,\- ]+", cleaned):
        raise ValidationError("Port spec may contain only digits, commas, hyphens and spaces")

    cleaned = re.sub(r"\s+", "", cleaned)
    if not cleaned:
        return None

    total = 0
    for token in cleaned.split(","):
        if not token:
            raise ValidationError(f"Empty port token in: {spec}")
        if "-" in token:
            lo, hi = token.split("-", 1)
            if not lo.isdigit() or not hi.isdigit():
                raise ValidationError(f"Invalid port range: {token}")
            lo_i, hi_i = int(lo), int(hi)
            if lo_i < 1 or hi_i > 65535 or lo_i > hi_i:
                raise ValidationError(f"Invalid port range: {token}")
            total += hi_i - lo_i + 1
        else:
            if not token.isdigit():
                raise ValidationError(f"Invalid port: {token}")
            p = int(token)
            if p < 1 or p > 65535:
                raise ValidationError(f"Port out of range: {p}")
            total += 1

    if total > 65535:
        raise ValidationError("Port spec exceeds 65535 ports")
    if total > 20000:
        raise ValidationError("Custom scan limited to 20,000 ports; use 'full' for all ports")

    return cleaned


def validate_scan_type(scan_type: str) -> str:
    allowed = {"quick", "standard", "full", "custom"}
    if scan_type not in allowed:
        raise ValidationError(f"scan_type must be one of: {', '.join(sorted(allowed))}")
    return scan_type


def resolve_hostname(hostname: str) -> Optional[str]:
    """Best-effort DNS resolution used by the agent (never the API, for safety)."""
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, OSError):
        return None


def is_private_target(target: str) -> bool:
    """True if every host in the target is RFC1918/loopback/link-local."""
    try:
        parts = [p.strip() for p in target.split(",") if p.strip()]
        for part in parts:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                if not (net.is_private or net.is_loopback or net.is_link_local):
                    return False
            else:
                try:
                    ip = ipaddress.ip_address(part)
                except ValueError:
                    continue  # hostname - cannot determine, assume public
                if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                    return False
        return True
    except ValueError:
        return False
