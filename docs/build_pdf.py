"""Build NetSentinel documentation: DOCUMENTATION.md -> DOCUMENTATION.html -> DOCUMENTATION.pdf.

HTML rendering uses python-markdown; PDF printing uses Microsoft Edge headless.
Run:  python docs/build_pdf.py
"""

import subprocess
import sys
from pathlib import Path

import markdown

DOCS = Path(__file__).parent
MD = DOCS / "DOCUMENTATION.md"
HTML = DOCS / "DOCUMENTATION.html"
PDF = DOCS / "DOCUMENTATION.pdf"
EDGE_CANDIDATES = [
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
]

CSS = """
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", Calibri, Arial, sans-serif;
  font-size: 10.5pt; line-height: 1.5; color: #1a2233; margin: 0;
}
h1 { font-size: 21pt; color: #1e2a4a; border-bottom: 3px solid #4f63d2;
     padding-bottom: 6pt; margin: 0 0 10pt; }
h2 { font-size: 14.5pt; color: #2c3a66; border-bottom: 1px solid #c9d2ea;
     padding-bottom: 3pt; margin: 20pt 0 8pt; page-break-after: avoid; }
h3 { font-size: 12pt; color: #2c3a66; margin: 14pt 0 6pt; page-break-after: avoid; }
p { margin: 5pt 0; }
table { border-collapse: collapse; width: 100%; margin: 8pt 0;
        font-size: 9.5pt; page-break-inside: avoid; }
th, td { border: 1px solid #b9c3dd; padding: 4pt 6pt; text-align: left;
         vertical-align: top; }
th { background: #eef1fa; color: #1e2a4a; }
tr:nth-child(even) td { background: #f7f8fc; }
code { font-family: Consolas, "Courier New", monospace; font-size: 9pt;
       background: #f0f2f8; padding: 1pt 3pt; border-radius: 3px; }
pre { background: #f5f6fb; border: 1px solid #d6dcf0; border-radius: 6px;
      padding: 8pt 10pt; overflow-x: hidden; page-break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8.5pt; line-height: 1.35; }
hr { border: none; border-top: 1px solid #c9d2ea; margin: 14pt 0; }
ul, ol { margin: 5pt 0 5pt 16pt; padding: 0; }
li { margin: 2pt 0; }
strong { color: #14203f; }
"""

PAGE_TMPL = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>NetSentinel Documentation</title>
<style>{css}</style></head>
<body>{body}</body></html>"""


def main() -> int:
    text = MD.read_text(encoding="utf-8")
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "sane_lists"])
    HTML.write_text(PAGE_TMPL.format(css=CSS, body=body), encoding="utf-8")
    print(f"HTML written: {HTML}")

    edge = next((p for p in EDGE_CANDIDATES if p.exists()), None)
    if edge is None:
        print("Edge not found; HTML is ready but PDF was not generated.")
        return 1

    cmd = [
        str(edge),
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={DOCS / '.edge-tmp'}",   # isolate from the running desktop Edge
        f"--print-to-pdf={PDF}",
        "--no-pdf-header-footer",
        "--virtual-time-budget=3000",
        HTML.as_uri(),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if PDF.exists() and PDF.stat().st_size > 10_000:
        print(f"PDF written: {PDF} ({PDF.stat().st_size / 1024:.0f} KB)")
        return 0
    print("PDF generation failed:", r.stderr[-500:] if r.stderr else r)
    return 1


if __name__ == "__main__":
    sys.exit(main())
