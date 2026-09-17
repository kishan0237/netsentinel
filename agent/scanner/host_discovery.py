"""Host discovery: find live hosts on the target network.

Three probes, best-effort and cross-platform:
1. ICMP ping (system `ping` binary) — reliable when not firewalled
2. ARP lookup for the local subnet (system `arp` table after a ping sweep)
3. TCP connect probe of common ports (443/80/22/445/3389) — catches hosts that drop ICMP
"""

import concurrent.futures as futures
import platform
import re
import socket
import subprocess
from typing import Optional

import ipaddress

COMMON_PROBE_PORTS = [443, 80, 22, 445, 3389, 5357]


def discover_hosts(target: str, max_hosts: int = 4096, timeout: float = 1.0) -> list[dict]:
    """Return a list of live hosts: [{ip_address, mac_address, hostname, status}]"""
    hosts: dict[str, dict] = {}
    networks: list[ipaddress._BaseNetwork] = []

    for part in [p.strip() for p in target.split(",") if p.strip()]:
        try:
            if "/" in part:
                networks.append(ipaddress.ip_network(part, strict=False))
            else:
                ip = ipaddress.ip_address(part)
                hosts[str(ip)] = {"ip_address": str(ip), "status": "up", "mac_address": None, "hostname": None}
        except ValueError:
            continue  # hostname — resolved by caller if needed

    candidates: list[str] = list(hosts.keys())
    for net in networks:
        if net.num_addresses > max_hosts:
            # Degrade gracefully: scan the first max_hosts addresses
            candidates += [str(h) for h in list(net.hosts())[:max_hosts]]
        else:
            candidates += [str(h) for h in net.hosts()]

    candidates = list(dict.fromkeys(candidates))[:max_hosts]

    with futures.ThreadPoolExecutor(max_workers=128) as pool:
        results = pool.map(lambda ip: _probe_host(ip, timeout), candidates)
    for ip, alive, mac in results:
        if alive:
            hosts[ip] = {"ip_address": ip, "status": "up", "mac_address": mac, "hostname": None}

    # Best-effort MAC + hostname enrichment for discovered hosts
    arp_table = _read_arp_table()
    for ip, info in hosts.items():
        info["mac_address"] = arp_table.get(ip)
        info["hostname"] = _reverse_lookup(ip)

    return list(hosts.values())


def _probe_host(ip: str, timeout: float) -> tuple[str, bool, Optional[str]]:
    alive = _icmp_ping(ip) or _tcp_probe(ip)
    mac = _arp_lookup(ip) if alive else None
    return ip, alive, mac


def _icmp_ping(ip: str) -> bool:
    param = "-n" if platform.system().lower() == "windows" else "-c"
    wait = "-w" if platform.system().lower() == "windows" else "-W"
    argv = ["ping", param, "1", wait, "1", ip]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=3, shell=False)
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _tcp_probe(ip: str) -> bool:
    for port in COMMON_PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=0.6):
                return True
        except OSError:
            continue
    return False


def _arp_lookup(ip: str) -> Optional[str]:
    return _read_arp_table().get(ip)


def _read_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    argv = ["arp", "-a"] if platform.system().lower() != "linux" else ["ip", "neigh"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=5, shell=False)
        for line in (r.stdout or "").splitlines():
            mac_match = re.search(
                r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line
            )
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if mac_match and ip_match:
                table[ip_match.group(1)] = mac_match.group(0).upper().replace("-", ":")
    except (subprocess.TimeoutExpired, OSError):
        pass
    return table


def _reverse_lookup(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, OSError):
        return None
