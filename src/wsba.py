#!/usr/bin/env python3
"""
WSBA - Web Security Baseline Audit (lightweight, safe-paste version)

Writes:
  - result.json
  - report.md

Even if checks fail (it still writes a report).
"""

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# --- Scoring (weights sum to 70; score starts at 100) ---
HEADER_WEIGHTS = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 25,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 5,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5,
}

def score_from_missing(missing: list[str]) -> dict:
    penalty = sum(HEADER_WEIGHTS.get(h, 0) for h in missing)
    score = max(0, 100 - penalty)

    if score >= 90:
        grade, level = "A", "excellent"
    elif score >= 80:
        grade, level = "B", "good"
    elif score >= 70:
        grade, level = "C", "fair"
    elif score >= 60:
        grade, level = "D", "weak"
    else:
        grade, level = "F", "poor"

    return {"score": score, "grade": grade, "level": level, "penalty": penalty}

# --- Severity + recommendations ---
SEVERITY_FOR_HEADER = {
    "Content-Security-Policy": "Medium",
    "Strict-Transport-Security": "Medium",
    "X-Frame-Options": "Low",
    "X-Content-Type-Options": "Low",
    "Referrer-Policy": "Info",
    "Permissions-Policy": "Info",
}

RECOMMENDED_VALUES = {
    "Strict-Transport-Security": "max-age=15552000; includeSubDomains; preload",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # CSP is site-specific; keep guidance general in report
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

def findings_from_missing(missing: list[str]) -> list[dict]:
    findings: list[dict] = []
    for h in missing:
        sev = SEVERITY_FOR_HEADER.get(h, "Info")
        rec = RECOMMENDED_VALUES.get(h, "Implement a secure default aligned to site requirements.")
        findings.append(
            {"title": f"Missing {h}", "severity": sev, "recommendation": rec}
        )

    order = {"Medium": 0, "Low": 1, "Info": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings

def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", str(e)

def dns_snapshot(target: str):
    if not have("dig"):
        return {"error": "dig not installed (sudo apt install -y dnsutils)"}
    out = {}
    for rtype in ["A", "AAAA", "MX", "TXT"]:
        rc, stdout, stderr = run(["dig", "+short", target, rtype], timeout=10)
        out[rtype] = stdout.splitlines() if stdout else []
        if rc != 0 and stderr:
            out[f"{rtype}_error"] = stderr
    return out

def http_headers(url: str):
    if not have("curl"):
        return {"error": "curl not installed (sudo apt install -y curl)"}
    rc, stdout, stderr = run(["curl", "-sS", "-D", "-", "-o", "/dev/null", url], timeout=20)
    if rc != 0:
        return {"error": stderr or f"curl exit {rc}"}

    # keep only the last header block (after redirects)
    blocks = [b for b in stdout.split("\n\n") if b.strip()]
    last = blocks[-1] if blocks else ""
    lines = [ln.strip("\r") for ln in last.splitlines() if ln.strip()]
    status = lines[0] if lines else ""

    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip()] = v.strip()

    return {"status_line": status, "headers": hdrs}

def tls_dates(target: str):
    if not have("openssl"):
        return {"error": "openssl not installed"}
    cmd = [
        "bash", "-lc",
        f"echo | openssl s_client -servername {target} -connect {target}:443 2>/dev/null | "
        "openssl x509 -noout -subject -issuer -dates"
    ]
    rc, stdout, stderr = run(cmd, timeout=25)
    if rc != 0:
        return {"error": stderr or f"openssl exit {rc}"}
    return {"raw": stdout}

def analyze_headers(hdrs: dict):
    present = {h: hdrs[h] for h in SEC_HEADERS if h in hdrs}
    missing = [h for h in SEC_HEADERS if h not in hdrs]
    return {"present": present, "missing": missing}

def to_md(result: dict) -> str:
    t = result["target"]
    url = result["url"]
    lines: list[str] = []

    # Title + metadata
    lines.append(f"# WSBA Report: `{t}`")
    lines.append("")
    lines.append(f"- URL tested: {url}")
    lines.append(f"- Timestamp (UTC): {result['timestamp_utc']}")
    lines.append("")

    # Score
    score = result.get("score")
    if score:
        lines.append("## Score")
        lines.append(f"- **Score:** {score.get('score')}/100")
        lines.append(f"- **Grade:** {score.get('grade')}")
        lines.append(f"- **Level:** {score.get('level')}")
        lines.append("")

    # Executive Summary
    findings = result.get("findings", [])
    if findings:
        lines.append("## Executive Summary")
        lines.append("Top findings based on missing security headers (non-intrusive baseline):")
        lines.append("")
        for f in findings[:3]:
            lines.append(f"- **[{f['severity']}]** {f['title']}")
        lines.append("")

        lines.append("## Recommended Header Set (Starting Point)")
        lines.append("Validate these against application requirements before deployment:")
        lines.append("")
        for f in findings:
            header_name = f["title"].replace("Missing ", "")
            if header_name == "Content-Security-Policy":
                lines.append("- **Content-Security-Policy**: start minimal (consider Report-Only), then tighten.")
            else:
                lines.append(f"- **{header_name}**: `{f['recommendation']}`")
        lines.append("")

    # DNS
    lines.append("## DNS Snapshot")
    dns = result.get("dns", {})
    if "error" in dns:
        lines.append(f"- Error: {dns['error']}")
    else:
        for k, v in dns.items():
            lines.append(f"- **{k}**: {', '.join(v) if v else '(none)'}")
    lines.append("")

    # HTTP
    lines.append("## HTTP Response")
    http = result.get("http", {})
    if "error" in http:
        lines.append(f"- Error: {http['error']}")
    else:
        lines.append(f"- Status line: {http.get('status_line') or '(unknown)'}")
    lines.append("")

    # Headers
    lines.append("## Security Headers")
    sec = result.get("security_headers", {})
    if "error" in sec:
        lines.append(f"- Error: {sec['error']}")
    else:
        if sec.get("present"):
            lines.append("### Present")
            for k, v in sec["present"].items():
                lines.append(f"- **{k}**: `{v}`")
        lines.append("")
        lines.append("### Missing / Not Observed")
        if sec.get("missing"):
            for h in sec["missing"]:
                lines.append(f"- **{h}**")
        else:
            lines.append("- None")
    lines.append("")

    # TLS
    lines.append("## TLS Certificate (Dates/Issuer)")
    tls = result.get("tls", {})
    if "error" in tls:
        lines.append(f"- Error: {tls['error']}")
    else:
        lines.append("```")
        lines.append(tls.get("raw", "").strip() or "(no tls output)")
        lines.append("```")
    lines.append("")

    # Notes
    lines.append("## Notes")
    lines.append("- Non-intrusive baseline audit. No exploitation performed.")
    lines.append("")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--scheme", default="https", choices=["http", "https"])
    args = ap.parse_args()

    target = args.target.strip()
    outdir = Path(args.out)
    ensure_dir(outdir)

    url = f"{args.scheme}://{target}/"

    result = {
        "target": target,
        "url": url,
        "timestamp_utc": now_utc(),
        "dns": dns_snapshot(target),
    }

    http = http_headers(url)
    result["http"] = http

    if "headers" in http:
        result["security_headers"] = analyze_headers(http["headers"])
        missing = result["security_headers"].get("missing", [])
        result["score"] = score_from_missing(missing)
        result["findings"] = findings_from_missing(missing)
    else:
        result["security_headers"] = {"error": "no headers to analyze"}
        result["score"] = {"score": 0, "grade": "F", "level": "unknown", "penalty": 100}
        result["findings"] = []

    result["tls"] = tls_dates(target) if args.scheme == "https" else {"skipped": "http scheme"}

    (outdir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(to_md(result), encoding="utf-8")

    print(f"[+] Wrote: {outdir/'result.json'}")
    print(f"[+] Wrote: {outdir/'report.md'}")

if __name__ == "__main__":
    main()

