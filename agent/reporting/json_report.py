"""Local JSON report writer."""

import json
from pathlib import Path


def write_json_report(results: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    scan_id = (results.get("scan") or {}).get("id", "local")
    path = out_dir / f"netsentinel-{scan_id[:8]}.json"
    path.write_text(json.dumps(results, indent=2, default=str))
    return path
