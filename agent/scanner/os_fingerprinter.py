"""OS fingerprinting: TTL/window heuristics (passive) + optional nmap -O."""

import platform
import subprocess
from typing import Optional

# Rough TTL signatures: initial TTL vs observed
TTL_SIGNATURES: list[tuple[int, str]] = [
    (64, "Linux/Unix/Android"),
    (128, "Windows"),
    (255, "Network device (Cisco/older Unix)"),
    (254, "Network device (Cisco)"),
    (128 - 1, "Windows"),  # common after a few hops
    (64 - 1, "Linux/Unix (1 hop)"),
]


def estimate_os_from_ttl(ttl: int) -> str:
    best, best_distance = "Unknown", 999
    for base, label in TTL_SIGNATURES:
        distance = abs(base - ttl)
        if distance < best_distance:
            best, best_distance = label, distance
    return best


def _observe_ttl(ip: str) -> Optional[int]:
    """Ping and parse the TTL from the reply header line (platform-dependent)."""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        r = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True,
                           timeout=4, shell=False)
        out = (r.stdout or "").lower()
        import re
        m = re.search(r"ttl[=:]\s*(\d+)", out)
        if m:
            return int(m.group(1))
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def fingerprint_os(ip: str) -> Optional[str]:
    ttl = _observe_ttl(ip)
    if ttl is None:
        return None
    return estimate_os_from_ttl(ttl)


def nmap_os_detect(target: str, timeout: int = 600) -> Optional[dict]:
    """Optional nmap-based OS detection (requires admin/root on most OSes)."""
    try:
        from agent.security.safe_nmap_execution import run_nmap, NmapExecutionError
        result = run_nmap(target, extra_flags=["-O", "-Pn", "-T4"], timeout=timeout)
        if result.returncode != 0:
            return None
        # Minimal parse of "OS details: ..." lines
        details: dict[str, str] = {}
        import re
        for m in re.finditer(r"OS details?:\s*(.+)", result.stdout or ""):
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", result.stdout[:m.start()][::-1] and result.stdout)
            details.setdefault("summary", m.group(1).strip())
            break
        return details or None
    except (ImportError, RuntimeError, ValueError, NmapExecutionError):
        return None
