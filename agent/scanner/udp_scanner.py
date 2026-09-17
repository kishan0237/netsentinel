"""UDP scanner — best-effort probe of common UDP services.

UDP state detection is inherently unreliable without raw sockets (ICMP
port-unreachable listening requires admin). We mark "open" only when a
service answers; silence is reported as open|filtered, which nmap calls
`open|filtered` — we approximate with `filtered` to stay honest.
"""

import socket
from typing import Optional

COMMON_UDP_PROBES: dict[int, bytes] = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
    123: b"\x1b" + 47 * b"\x00",                               # NTP
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
    137: b"\x00",                                              # NetBIOS NS
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_local\x00\x00\x0c\x00\x01",  # mDNS
}


def scan_udp_ports(ip: str, ports: Optional[list[int]] = None, timeout: float = 1.0) -> list[dict]:
    """Probe common UDP ports. Only ports that answer are reported open."""
    targets = ports if ports else sorted(COMMON_UDP_PROBES.keys())
    results: list[dict] = []
    for port in targets:
        payload = COMMON_UDP_PROBES.get(port, b"\x00")
        state = _probe(ip, port, payload, timeout)
        if state == "open":
            results.append({"port_number": port, "protocol": "udp", "state": state})
    return results


def _probe(ip: str, port: int, payload: bytes, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            try:
                s.recvfrom(1024)
                return "open"
            except ConnectionRefusedError:
                return "closed"
            except socket.timeout:
                return "filtered"
    except OSError:
        return "filtered"
