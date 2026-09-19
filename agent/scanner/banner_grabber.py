"""Banner grabbing: read service greetings from open TCP ports."""

import socket
import ssl
from typing import Optional

GRAB_TIMEOUT = 1.5
MAX_BANNER = 512

# Ports where a TLS handshake first gets more info
TLS_PORTS = {443, 465, 563, 614, 636, 989, 990, 992, 993, 995, 3389, 5061, 8443}


def grab_banner(ip: str, port: int) -> Optional[str]:
    """Connect and read the initial bytes the service sends, if any."""
    try:
        with socket.create_connection((ip, port), timeout=GRAB_TIMEOUT) as sock:
            sock.settimeout(GRAB_TIMEOUT)
            if port in TLS_PORTS:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                        cert = tls.getpeercert(binary_form=False)
                        banner = _read_some(tls)
                        if cert:
                            subject = dict(x[0] for x in cert.get("subject", []))
                            cn = subject.get("commonName", "")
                            banner = f"TLS CN={cn} {banner}".strip()
                        return (banner or None)
                except (ssl.SSLError, OSError):
                    pass
            return _read_some(sock)
    except OSError:
        return None


def _read_some(sock) -> Optional[str]:
    try:
        data = sock.recv(MAX_BANNER)
        if data:
            text = data.decode("utf-8", errors="replace")
            # Binary protocols (MySQL handshakes etc.) send NUL/control bytes:
            # PostgreSQL cannot store them, so strip before use.
            text = text.translate(_BANNER_CLEANUP)
            return text.strip()[:MAX_BANNER] or None
    except (socket.timeout, OSError):
        pass
    return None


# Drop NUL, DEL and C0 control chars (keep tab/newline/carriage-return)
_BANNER_CLEANUP = {c: None for c in range(32) if c not in (9, 10, 13)}
_BANNER_CLEANUP[0x7F] = None
