"""The NetSentinel scan pipeline.

Stages (matching the architecture):
target validation -> host discovery -> port discovery -> service detection
-> banner grab -> version detection -> OS fingerprint -> CVE enrichment
-> risk engine -> results tree (findings included).
"""

import concurrent.futures as futures
import ipaddress
import logging
import re
import socket
from typing import Any, Callable, Optional

from agent.scanner import banner_grabber, host_discovery, service_detector, tcp_scanner
from agent.scanner.async_scanner import scan_tcp_ports_async
from agent.scanner.nmap_engine import nmap_available, run_nmap_scan
from agent.risk import risk_engine
from agent.vulnerability import vulnerability_checks
from agent.vulnerability.cve_matcher import enrich_hosts

logger = logging.getLogger("netsentinel.agent")

ProgressCb = Callable[[int, str], None]

TOP_100 = 100
TOP_1000 = 1000
ALL_PORTS = list(range(1, 65536))
MAX_HOSTS = 4096


class ScanPipeline:
    def run(self, target: str, scan_type: str = "standard",
            ports_spec: Optional[str] = None,
            on_progress: Optional[ProgressCb] = None) -> dict[str, Any]:
        report = lambda pct, stage: on_progress(pct, stage) if on_progress else None

        # Stage 1: target validation ---------------------------------------
        report(5, "target_validation")
        normalized = self._validate_target(target)

        # Stage 2: host discovery ------------------------------------------
        report(12, "host_discovery")
        hosts = host_discovery.discover_hosts(normalized, max_hosts=MAX_HOSTS)
        logger.info("Host discovery: %d live host(s)", len(hosts))
        if not hosts:
            return self._finish([], normalized, scan_type)

        # Stage 3: port discovery --------------------------------------------
        report(30, "port_scanning")
        port_list = self._resolve_ports(scan_type, ports_spec)
        use_nmap = nmap_available() and scan_type != "custom"

        if use_nmap:
            logger.info("nmap detected — using nmap -sV for service detection")
            report(40, "port_scanning(nmap)")
            nmap_hosts = run_nmap_scan(
                normalized,
                ports=ports_spec if scan_type == "custom" else None,
                service_detection=True,
            )
            if nmap_hosts:
                # Keep nmap's richer data; merge discovery-only metadata
                by_ip = {h["ip_address"]: h for h in nmap_hosts}
                for disc in hosts:
                    if disc["ip_address"] in by_ip:
                        h = by_ip[disc["ip_address"]]
                        if not h.get("hostname") and disc.get("hostname"):
                            h["hostname"] = disc["hostname"]
                        if not h.get("mac_address") and disc.get("mac_address"):
                            h["mac_address"] = disc["mac_address"]
                    else:  # discovered by pure-Python probes but missed by nmap
                        nmap_hosts.append({
                            "ip_address": disc["ip_address"], "hostname": disc.get("hostname"),
                            "mac_address": disc.get("mac_address"), "os_estimate": None,
                            "status": "up", "ports": [],
                        })
                hosts = nmap_hosts
        else:
            hosts = self._pure_python_port_scan(hosts, port_list, report)

        # Stage 4: OS fingerprint (heuristic TTL) ----------------------------
        report(70, "os_fingerprint")
        for h in hosts:
            if not h.get("os_estimate"):
                est = self._os_estimate(h["ip_address"])
                if est:
                    h["os_estimate"] = est

        # Stage 5: CVE enrichment --------------------------------------------
        report(80, "cve_enrichment")
        enrich_hosts(hosts)

        # Stage 6: active checks + findings via risk engine -------------------
        report(90, "risk_analysis")
        extra_findings: list[dict] = []
        for h in hosts:
            for p in h.get("ports", []):
                for svc in p.get("services", []):
                    extra_findings += vulnerability_checks.run_active_checks(
                        h["ip_address"], svc.get("service_name", ""), p.get("port_number", 0)
                    )

        findings = risk_engine.generate_findings(hosts) + extra_findings
        return self._finish(hosts, normalized, scan_type, findings)

    # ------------------------------------------------------------------ parts
    def _validate_target(self, target: str) -> str:
        target = (target or "").strip()
        if not target or len(target) > 255:
            raise ValueError("Invalid target")
        if re.search(r"[;&|`$<>\\'\"]", target):
            raise ValueError("Target contains forbidden characters")
        parts = [p.strip() for p in target.split(",") if p.strip()]
        for part in parts:
            if "/" in part:
                try:
                    net = ipaddress.ip_network(part, strict=False)
                    if net.num_addresses > MAX_HOSTS:
                        raise ValueError(f"CIDR too large: {part}")
                except ValueError as e:
                    raise ValueError(f"Invalid CIDR: {part}") from e
            else:
                try:
                    ipaddress.ip_address(part)
                except ValueError:
                    resolved = self._resolve_hostname(part)
                    if not resolved:
                        raise ValueError(f"Cannot resolve host: {part}")
        return ",".join(parts)

    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        try:
            return socket.gethostbyname(hostname)
        except OSError:
            return None

    def _resolve_ports(self, scan_type: str, ports_spec: Optional[str]) -> list[int]:
        if scan_type == "quick":
            return tcp_scanner.top_ports(TOP_100)
        if scan_type == "standard":
            return tcp_scanner.top_ports(TOP_1000)
        if scan_type == "full":
            return ALL_PORTS
        if scan_type == "custom" and ports_spec:
            ports: list[int] = []
            for token in ports_spec.split(","):
                if "-" in token:
                    lo, hi = token.split("-", 1)
                    ports.extend(range(int(lo), int(hi) + 1))
                elif token.strip().isdigit():
                    ports.append(int(token))
            return sorted(set(ports))
        return tcp_scanner.top_ports(TOP_1000)

    def _pure_python_port_scan(self, hosts: list[dict], port_list: list[int],
                               report: Callable) -> list[dict]:
        ips = [h["ip_address"] for h in hosts]

        def scan_one(ip: str):
            return ip, scan_tcp_ports_async(ip, port_list, timeout=0.8, concurrency=1000)

        open_ports_by_ip: dict[str, list[dict]] = {}
        with futures.ThreadPoolExecutor(max_workers=min(64, max(1, len(ips)))) as pool:
            futs = {pool.submit(scan_one, ip): ip for ip in ips}
            done = 0
            for fut in futures.as_completed(futs):
                ip, port_states = fut.result()
                open_ports_by_ip[ip] = [p for p in port_states if p["state"] == "open"]
                done += 1
                report(30 + int(35 * done / max(1, len(ips))), "port_scanning")

        for h in hosts:
            enriched_ports = []
            for p in open_ports_by_ip.get(h["ip_address"], []):
                banner = banner_grabber.grab_banner(h["ip_address"], p["port_number"])
                svc = service_detector.detect_service(h["ip_address"], p["port_number"], banner)
                enriched_ports.append({**p, "services": [svc]})
            h["ports"] = enriched_ports
        return hosts

    def _os_estimate(self, ip: str) -> Optional[str]:
        try:
            from agent.scanner.os_fingerprinter import fingerprint_os
            return fingerprint_os(ip)
        except Exception:
            return None

    def _finish(self, hosts: list[dict], target: str, scan_type: str,
                findings: Optional[list[dict]] = None) -> dict[str, Any]:
        if findings is None:
            findings = risk_engine.generate_findings(hosts)
        open_ports = sum(len(h.get("ports", [])) for h in hosts)
        return {
            "scan": {"target": target, "scan_type": scan_type},
            "hosts": hosts,
            "findings": findings,
            "stats": {
                "hosts": len(hosts),
                "open_ports": open_ports,
                "services": sum(len(p.get("services", [])) for h in hosts for p in h.get("ports", [])),
                "vulnerabilities": sum(
                    len(svc.get("vulnerabilities", []))
                    for h in hosts for p in h.get("ports", []) for svc in p.get("services", [])
                ),
                "findings": len(findings),
                "severity_counts": risk_engine.severity_summary(findings),
                "risk_score": risk_engine.overall_risk_score(findings),
            },
        }


def run_scan(target: str, scan_type: str = "standard", ports: Optional[str] = None,
             on_progress: Optional[ProgressCb] = None) -> dict[str, Any]:
    """Convenience function used by the agent loop and CLI."""
    return ScanPipeline().run(target, scan_type, ports, on_progress)
