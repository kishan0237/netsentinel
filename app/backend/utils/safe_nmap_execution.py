"""Safe nmap execution helpers.

Used by the agent on the user's machine (and importable by the backend for
testing). Guarantees: argv-list execution (no shell), fixed first element
(nmap binary), `--` before the target to prevent option injection, timeouts,
and output size caps.
"""

import os
import shutil
import subprocess
from typing import Optional


class NmapExecutionError(RuntimeError):
    """Raised when nmap cannot be executed safely."""


ALLOWED_NMAP_FLAGS = {
    "-sV", "-sT", "-sU", "-sP", "-sn", "-Pn", "-O", "-A", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--top-ports", "--version-light", "--version-all", "--osscan-limit", "--max-retries",
    "--min-rate", "--max-rate", "--open", "--host-timeout",
}
# NOTE: value-taking flags with security implications (-p, --script, --script-args)
# are excluded here; they are only added via their dedicated, validated parameters.


def find_nmap() -> Optional[str]:
    """Locate the nmap binary on this machine (agent-side)."""
    path = shutil.which("nmap")
    if path:
        return path
    # Common Windows install location
    for cand in (
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ):
        if os.path.exists(cand):
            return cand
    return None


def build_nmap_command(
    target: str,
    ports: Optional[str] = None,
    extra_flags: Optional[list] = None,
    scripts: Optional[list] = None,
) -> list:
    """Build a safe nmap argv list.

    - target must already be validated by app.backend.utils.input_validation
    - the literal `--` is inserted before the target so nmap cannot interpret it
      as options (argument-injection protection)
    - only whitelisted flags are allowed
    """
    flags = list(extra_flags or [])
    for f in flags:
        if f not in ALLOWED_NMAP_FLAGS:
            raise NmapExecutionError(f"nmap flag not allowed: {f}")

    argv = [find_nmap() or "nmap"]
    argv += flags
    if ports:
        argv += ["-p", ports]
    if scripts:
        argv += ["--script", ",".join(scripts)]
    argv += ["--"]  # end-of-options marker: everything after is targets only
    argv.append(target)
    return argv


def run_nmap(
    target: str,
    ports: None = None,
    extra_flags: Optional[list] = None,
    scripts: Optional[list] = None,
    timeout: int = 600,
) -> subprocess.CompletedProcess:
    """Run nmap with argv-list (no shell), timeout, and output caps."""
    argv = build_nmap_command(target, ports=ports, extra_flags=extra_flags, scripts=scripts)
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env={**os.environ, "PATH": os.environ.get("PATH", "")},
        )
    except FileNotFoundError as e:
        raise NmapExecutionError("nmap binary not found on this machine") from e
    except subprocess.TimeoutExpired as e:
        raise NmapExecutionError(f"nmap timed out after {timeout}s") from e

    # Cap retained output to avoid memory blowups on huge scans
    max_bytes = 4 * 1024 * 1024
    if result.stdout and len(result.stdout.encode()) > max_bytes:
        result = subprocess.CompletedProcess(
            argv, result.returncode,
            stdout=result.stdout[:max_bytes] + "\n...[truncated]",
            stderr=result.stderr,
        )
    return result
