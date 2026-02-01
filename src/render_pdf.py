#!/usr/bin/env python3
"""
Reliable PDF renderer for WSBA final_report.md

Usage:
  python3 src/render_pdf.py reports/example-com/final_report.md reports/example-com/final_report.pdf
"""

import sys
from pathlib import Path
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas

PAGE_W, PAGE_H = LETTER
MARGIN = 54
LINE_GAP = 14

def main() -> int:
    print("[render_pdf] starting...")

    if len(sys.argv) != 3:
        print("Usage: python3 src/render_pdf.py <input.md> <output.pdf>")
        return 1

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    print(f"[render_pdf] input:  {in_path}")
    print(f"[render_pdf] output: {out_path}")

    if not in_path.exists():
        print(f"[render_pdf] ERROR: input file not found: {in_path}")
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines = in_path.read_text(encoding="utf-8").splitlines()
    print(f"[render_pdf] lines read: {len(lines)}")

    c = canvas.Canvas(str(out_path), pagesize=LETTER)

    y = PAGE_H - MARGIN

    # Simple markdown-ish formatting:
    for raw in lines:
        line = raw.rstrip()

        if not line.strip():
            y -= LINE_GAP // 2
            if y < MARGIN:
                c.showPage()
                y = PAGE_H - MARGIN
            continue

        # Headings
        if line.startswith("# "):
            c.setFont("Helvetica-Bold", 18)
            y -= 8
            c.drawString(MARGIN, y, line[2:].strip())
            y -= 24
            continue

        if line.startswith("## "):
            c.setFont("Helvetica-Bold", 14)
            y -= 6
            c.drawString(MARGIN, y, line[3:].strip())
            y -= 18
            continue

        if line.startswith("### "):
            c.setFont("Helvetica-Bold", 12)
            c.drawString(MARGIN, y, line[4:].strip())
            y -= 16
            continue

        # Bullets
        if line.startswith("- "):
            line = "• " + line[2:].strip()

        # Normal text
        c.setFont("Helvetica", 11)

        # Basic wrap (very simple): split long lines
        max_chars = 110
        while len(line) > max_chars:
            chunk = line[:max_chars]
            c.drawString(MARGIN, y, chunk)
            y -= LINE_GAP
            line = line[max_chars:]
            if y < MARGIN:
                c.showPage()
                y = PAGE_H - MARGIN
                c.setFont("Helvetica", 11)

        c.drawString(MARGIN, y, line)
        y -= LINE_GAP

        if y < MARGIN:
            c.showPage()
            y = PAGE_H - MARGIN

    c.save()

    size = out_path.stat().st_size if out_path.exists() else 0
    print(f"[render_pdf] DONE. wrote {out_path} ({size} bytes)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
