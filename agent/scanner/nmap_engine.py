"""Nmap auxiliary engine: use nmap when available, pure-Python otherwise.

The pure-Python pipeline (host discovery + async TCP + banner grab + service
detect) works everywhere with zero dependencies; when nmap is installed we
prefer its -sV XML output for richer service/version data.
"""

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional


def find_nmap() -> Optional[str]:
    path = shutil.which("nmap")
    if path:
        return path
    for cand in (
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ):
        if os.path.exists(cand):
            return cand
    return None


def nmap_available() -> bool:
    return find_nmap() is not None


def run_nmap_scan(target: str, ports: Optional[str] = None,
                  service_detection: bool = True, timeout: int = 1800) -> Optional[list[dict]]:
    """Run nmap and return [{ip, hostname, mac, os_estimate, ports:[...]}].

    Returns None if nmap is unavailable or fails, so callers can fall back to
    the pure-Python scanner.
    """
    binary = find_nmap()
    if not binary:
        return None

    argv = [binary, "-sn", "-T4", "--", target] if service_detection is False else [
        binary, "-sV", "-T4", "--", target
    ]
    if ports:
        argv += ["-p", str(ports)]

    try:
        proc = subprocess.run(
            argv + ["-oX", "-"], capture_output=True, text=True, timeout=timeout, shell=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return parse_nmap_xml(proc.stdout)


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML into the pipeline's host/port/service structures."""
    hosts: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host_el in root.iter("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else None
        if not ip:
            continue

        mac_el = host_el.find("address[@addrtype='mac']")
        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        os_estimate = None
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_estimate = match.get("name")

        host: dict = {
            "ip_address": ip,
            "hostname": hostname,
            "mac_address": mac_el.get("addr") if mac_el is not None else None,
            "os_estimate": os_estimate,
            "status": "up",
            "ports": [],
        }

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.iter("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") not in ("open", "open|filtered"):
                    continue
                port_id, protocol = int(port_el.get("portid")), port_el.get("protocol", "tcp")
                service_entry = {
                    "port_number": port_id,
                    "protocol": protocol,
                    "state": "open",
                    "services": [],
                }
                svc_el = port_el.find("service")
                if svc_el is not None:
                    service_entry["services"] = [{
                        "service_name": svc_el.get("name") or f"port-{port_id}",
                        "product": svc_el.get("product"),
                        "version": svc_el.get("version"),
                        "banner": None,
                        "vulnerabilities": [],
                    }]
                else:
                    service_entry["services"] = [{
                        "service_name": f"port-{port_id}", "product": None,
                        "version": None, "banner": None, "vulnerabilities": [],
                    }]
                host["ports"].append(service_entry)

        hosts.append(host)
    return hosts
