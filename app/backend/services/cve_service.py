"""CVE enrichment service.

Strategy:
1. Offline curated feed of common service/version CVEs (works with no internet).
2. Optional NVD API 2.0 lookup (server-side) when NVD_API_KEY is set — kept
   non-fatal so scans never fail because of enrichment.
"""

import logging
import os
import re
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 10

# Curated feed: (service_name_or_product_lower, version_prefix) -> list of CVE dicts.
# version_prefix None means "any version".
_CURATED: list[dict[str, Any]] = [
    {
        "match": ("openssh", None), "max_version": "9.6",
        "cves": [
            {"cve_id": "CVE-2023-38408", "severity": "critical", "cvss_score": 9.8,
             "description": "OpenSSH ssh-agent remote code execution via PKCS#11 module loading.",
             "solution": "Upgrade OpenSSH to 9.3p2 or later."},
            {"cve_id": "CVE-2024-6387", "severity": "critical", "cvss_score": 8.1,
             "description": "regreSSHion: signal handler race condition allows unauthenticated RCE on glibc-based systems.",
             "solution": "Upgrade OpenSSH to 9.8p1 or apply vendor patch."},
        ],
    },
    {
        "match": ("nginx", None), "max_version": "1.24.0",
        "cves": [
            {"cve_id": "CVE-2021-23017", "severity": "high", "cvss_score": 8.7,
             "description": "DNS resolver off-by-one heap overwrite allows RCE or DoS.",
             "solution": "Upgrade nginx to 1.21.0+ or 1.20.1+."},
        ],
    },
    {
        "match": ("apache", None), "max_version": "2.4.57",
        "cves": [
            {"cve_id": "CVE-2021-41773", "severity": "critical", "cvss_score": 9.8,
             "description": "Path traversal and RCE in Apache 2.4.49/2.4.50 when mod_cgi is enabled.",
             "solution": "Upgrade Apache HTTP Server to 2.4.51 or later."},
            {"cve_id": "CVE-2024-38474", "severity": "high", "cvss_score": 7.5,
             "description": "Encoding issue in mod_rewrite may allow script execution in some configurations.",
             "solution": "Upgrade Apache HTTP Server to 2.4.60 or later."},
        ],
    },
    {
        "match": ("mysql", None), "max_version": "8.0.34",
        "cves": [
            {"cve_id": "CVE-2023-22084", "severity": "medium", "cvss_score": 6.5,
             "description": "MySQL Server unspecified vulnerability allowing privileged escalation.",
             "solution": "Upgrade MySQL Server to the latest vendor patch set."},
        ],
    },
    {
        "match": ("microsoft iis", None), "max_version": "10.0",
        "cves": [
            {"cve_id": "CVE-2021-31166", "severity": "high", "cvss_score": 7.5,
             "description": "HTTP Protocol Stack DoS via malformed requests.",
             "solution": "Apply Microsoft May 2021 cumulative updates."},
        ],
    },
    {
        "match": ("vsftpd", None), "max_version": "3.0.3",
        "cves": [
            {"cve_id": "CVE-2015-1419", "severity": "high", "cvss_score": 7.5,
             "description": "Configurable-file race allows unauthorized file modification in vsftpd.",
             "solution": "Upgrade vsftpd to 3.0.3+ with vendor patches."},
        ],
    },
    {
        "match": ("postgresql", None), "max_version": "15.3",
        "cves": [
            {"cve_id": "CVE-2024-10977", "severity": "medium", "cvss_score": 6.2,
             "description": "Row security policies may leak data via secondary queries on id columns.",
             "solution": "Upgrade PostgreSQL to 17.1/16.5/15.9 or later."},
        ],
    },
    {
        "match": ("redis", None), "max_version": "7.0.11",
        "cves": [
            {"cve_id": "CVE-2022-24834", "severity": "critical", "cvss_score": 9.8,
             "description": "Lua script crafted integer overflow in Redis allows RCE.",
             "solution": "Upgrade Redis to 6.2.16 / 7.0.15 or later."},
        ],
    },
    {
        "match": ("ftp", None), "max_version": None,
        "cves": [
            {"cve_id": "CVE-1999-0415", "severity": "medium", "cvss_score": 5.0,
             "description": "FTP bounce attack: server permits connections to third parties via PORT command.",
             "solution": "Disable PORT relay or restrict FTP access."},
        ],
    },
    {
        "match": ("telnet", None), "max_version": None,
        "cves": [
            {"cve_id": "CVE-1999-0619", "severity": "high", "cvss_score": 7.5,
             "description": "Telnet transmits credentials in cleartext.",
             "solution": "Disable Telnet; use SSH instead."},
        ],
    },
]

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _version_tuple(v: str) -> tuple:
    parts = []
    for piece in re.split(r"[.\-+~]", v):
        if piece.isdigit():
            parts.append(int(piece))
        else:
            m = re.match(r"(\d+)", piece)
            if m:
                parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _version_lte(a: str, b: str) -> bool:
    try:
        return _version_tuple(a) <= _version_tuple(b)
    except (TypeError, ValueError):
        return False


def match_service(service_name: str, product: Optional[str], version: Optional[str]) -> list[dict[str, Any]]:
    """Return curated CVE dicts matching this service/product/version."""
    name_l = (service_name or "").lower()
    prod_l = (product or "").lower()
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for entry in _CURATED:
        match_key, _ = entry["match"]
        if match_key not in name_l and match_key not in prod_l:
            continue
        max_ver = entry.get("max_version")
        if max_ver and version and not _version_lte(version, max_ver):
            continue  # version newer than the vulnerable ceiling
        for cve in entry["cves"]:
            if cve["cve_id"] in seen:
                continue
            seen.add(cve["cve_id"])
            results.append({**cve, "confidence": "medium"})

    return results


def fetch_nvd_cves(product: str, version: Optional[str], api_key: Optional[str] = None) -> list[dict[str, Any]]:
    """Query NVD API 2.0 for a CPE-ish keyword. Non-fatal on any error."""
    key = api_key or os.getenv("NVD_API_KEY")
    params = {"keywordSearch": f"{product} {version or ''}".strip(), "resultsPerPage": 10}
    headers = {"apiKey": key} if key else {}
    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=NVD_TIMEOUT)
        if resp.status_code != 200:
            return []
        data = resp.json()
        out = []
        for item in (data.get("vulnerabilities") or []):
            cve = (item.get("cve") or {})
            cve_id = cve.get("id")
            if not cve_id or not _CVE_RE.match(cve_id):
                continue
            metrics = cve.get("metrics", {})
            score, severity, vector = None, "medium", None
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(metric_key) or []
                if arr:
                    primary = arr[0].get("cvssData", {})
                    score = primary.get("baseScore")
                    vector = primary.get("vectorString")
                    severity = (arr[0].get("baseSeverity")
                                or primary.get("baseSeverity") or "medium").lower()
                    break
            out.append({
                "cve_id": cve_id,
                "severity": severity if severity in ("critical", "high", "medium", "low", "info") else "medium",
                "cvss_score": float(score) if score is not None else None,
                "description": next(
                    (d.get("value") for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), None),
                "solution": None,
                "confidence": "high" if score is not None else "low",
            })
        return out
    except (requests.RequestException, ValueError) as e:
        logger.debug("NVD lookup failed for %s: %s", product, e)
        return []


def enrich_service(service_name: str, product: Optional[str], version: Optional[str],
                   use_nvd: bool = False) -> list[dict[str, Any]]:
    """Full enrichment for one detected service."""
    curated = match_service(service_name, product, version)
    if use_nvd and product:
        nvd = fetch_nvd_cves(product, version)
        seen = {c["cve_id"] for c in curated}
        curated.extend(c for c in nvd if c["cve_id"] not in seen)
    return curated
