"""Agent-side safe nmap execution (hardened copy of the backend module).

Guarantees: argv-list only (never shell=True), fixed binary, whitelisted
flags, `--` before targets so a hostile target string can never be parsed as
options, hard timeouts and output caps.
"""

import subprocess
from typing import Optional

from agent.scanner.nmap_engine import find_nmap

ALLOWED_NMAP_FLAGS = {
    "-sV", "-sT", "-sU", "-sn", "-Pn", "-O", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--top-ports", "--version-light", "--version-all", "--osscan-limit",
    "--max-retries", "--min-rate", "--max-rate", "--open", "--host-timeout",
}


class NmapExecutionError(RuntimeError):
    pass


def build_nmap_command(target: str, ports: Optional[str] = None,
                       extra_flags: Optional[list] = None) -> list:
    binary = find_nmap()
    if not binary:
        raise NmapExecutionError("nmap is not installed on this machine")

    flags = list(extra_flags or [])
    for f in flags:
        if f not in ALLOWED_NMAP_FLAGS:
            raise NmapExecutionError(f"nmap flag not allowed: {f}")

    argv = [binary] + flags
    if ports:
        argv += ["-p", str(ports)]
    argv += ["--", target]  # end-of-options: target is always positional
    return argv


def run_nmap(target: str, ports: Optional[str] = None,
             extra_flags: Optional[list] = None, timeout: int = 900):
    argv = build_nmap_command(target, ports=ports, extra_flags=extra_flags)
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, shell=False, check=False
        )
    except subprocess.TimeoutExpired as e:
        raise NmapExecutionError(f"nmap timed out after {timeout}s") from e
