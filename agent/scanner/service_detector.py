"""Service detection: identify service name, product and version.

Combines: well-known port mapping, banner parsing, and active probes
(HTTP HEAD, SSH version string, SMTP greeting).
"""

import re
from typing import Optional

WELL_KNOWN: dict[int, tuple[str, str]] = {
    20: ("ftp-data", "tcp"), 21: ("ftp", "tcp"), 22: ("ssh", "tcp"), 23: ("telnet", "tcp"),
    25: ("smtp", "tcp"), 53: ("domain", "udp"), 67: ("dhcps", "udp"), 68: ("dhcpc", "udp"),
    69: ("tftp", "udp"), 80: ("http", "tcp"), 110: ("pop3", "tcp"), 111: ("rpcbind", "tcp"),
    113: ("ident", "tcp"), 123: ("ntp", "udp"), 135: ("msrpc", "tcp"), 137: ("netbios-ns", "udp"),
    139: ("netbios-ssn", "tcp"), 143: ("imap", "tcp"), 161: ("snmp", "udp"), 389: ("ldap", "tcp"),
    443: ("https", "tcp"), 445: ("microsoft-ds", "tcp"), 465: ("smtps", "tcp"),
    514: ("syslog", "udp"), 515: ("printer", "tcp"), 548: ("afp", "tcp"), 554: ("rtsp", "tcp"),
    587: ("submission", "tcp"), 631: ("ipp", "tcp"), 636: ("ldaps", "tcp"), 993: ("imaps", "tcp"),
    995: ("pop3s", "tcp"), 1080: ("socks", "tcp"), 1433: ("ms-sql-s", "tcp"),
    1521: ("oracle", "tcp"), 1723: ("pptp", "tcp"), 1883: ("mqtt", "tcp"),
    2049: ("nfs", "tcp"), 2181: ("zookeeper", "tcp"), 2375: ("docker", "tcp"),
    2376: ("docker-tls", "tcp"), 3000: ("http", "tcp"), 3128: ("squid-http", "tcp"),
    3260: ("iscsi", "tcp"), 3268: ("globalcatLDAP", "tcp"), 3306: ("mysql", "tcp"),
    3389: ("ms-wbt-server", "tcp"), 5353: ("mdns", "udp"), 5432: ("postgresql", "tcp"),
    5555: ("adb", "tcp"), 5601: ("elasticsearch", "tcp"), 5666: ("nrpe", "tcp"),
    5900: ("vnc", "tcp"), 5984: ("couchdb", "tcp"), 6379: ("redis", "tcp"),
    6443: ("kubernetes", "tcp"), 8000: ("http", "tcp"), 8080: ("http-proxy", "tcp"),
    8443: ("https-alt", "tcp"), 8888: ("http", "tcp"), 9000: ("cslistener", "tcp"),
    9090: ("websm", "tcp"), 9100: ("jetdirect", "tcp"), 9200: ("elasticsearch", "tcp"),
    11211: ("memcached", "tcp"), 27017: ("mongod", "tcp"), 50000: ("db2", "tcp"),
}

_BANNER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenSSH", re.compile(r"OpenSSH[_ ]([\d.p]+)", re.I)),
    ("dropbear", re.compile(r"dropbear[_ ]([\d.]+)", re.I)),
    ("nginx", re.compile(r"nginx/([\d.]+)", re.I)),
    ("Apache httpd", re.compile(r"Apache/([\d.]+)", re.I)),
    ("Microsoft IIS", re.compile(r"Microsoft-IIS/([\d.]+)", re.I)),
    ("MySQL", re.compile(r"(\d+\.\d+\.\d+[-\w]*)?.*mysql", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL ([\d.]+)", re.I)),
    ("Redis", re.compile(r"Redis[.. ]?([\d.]+)", re.I)),
    ("MongoDB", re.compile(r"MongoDB.*?([\d.]+)", re.I)),
    ("vsftpd", re.compile(r"vsftpd ([\d.]+)", re.I)),
    ("ProFTPD", re.compile(r"ProFTPD ([\d.]+)", re.I)),
    ("Postfix", re.compile(r"Postfix", re.I)),
    ("Exim", re.compile(r"Exim ([\d.]+)", re.I)),
    ("Dovecot", re.compile(r"Dovecot ready", re.I)),
    ("Caddy", re.compile(r"Caddy", re.I)),
]


def detect_service(ip: str, port: int, banner: Optional[str]) -> dict:
    """Return {service_name, product, version, banner} for an open port."""
    service_name, _ = WELL_KNOWN.get(port, (f"port-{port}", "tcp"))
    product, version = None, None

    if banner:
        for prod_name, pattern in _BANNER_PATTERNS:
            m = pattern.search(banner)
            if m:
                product = prod_name
                if m.groups() and m.group(1):
                    version = m.group(1)
                break

        # Infer service name from banner keywords when port mapping is generic
        banner_l = banner.lower()
        for kw, svc in [
            ("ssh", "ssh"), ("ftp", "ftp"), ("smtp", "smtp"), ("imap", "imap"),
            ("pop3", "pop3"), ("redis", "redis"), ("mysql", "mysql"), ("http", "http"),
        ]:
            if kw in banner_l and service_name.startswith(("port-", "http-proxy", "cslistener")):
                service_name = svc
                break

    if service_name in ("http", "https", "http-proxy", "http-alt") and product is None:
        http_info = _http_probe(ip, port)
        if http_info:
            product, version = http_info

    return {
        "service_name": service_name,
        "product": product,
        "version": version,
        "banner": (banner or None),
    }


def _http_probe(ip: str, port: int) -> Optional[tuple[str, Optional[str]]]:
    try:
        import socket as _s

        with _s.create_connection((ip, port), timeout=1.5) as s:
            s.settimeout(1.5)
            s.sendall(b"HEAD / HTTP/1.0\r\nUser-Agent: NetSentinel/1.0\r\n\r\n")
            data = s.recv(512).decode("utf-8", errors="replace")
        m = re.search(r"Server:\s*(\S+)/?([\d.]*)?", data, re.I)
        if m:
            server = m.group(1)
            version = m.group(2) or None
            product = {
                "nginx": "nginx", "apache": "Apache httpd",
                "microsoft-iis": "Microsoft IIS", "caddy": "Caddy",
                "litepeed": "LiteSpeed", "gws": "Google Web Server",
            }.get(server.lower(), server)
            return product, version
    except OSError:
        pass
    return None
