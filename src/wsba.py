#!/usr/bin/env python3
"""
WSBA - Web Security Baseline Audit (lightweight, safe-paste version)
Writes:
  - result.json
  - report.md
Even if checks fail (it still writes a report).
"""

import argparse, json, shutil, subprocess
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


def now_utc():
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
    lines = []
    lines.append(f"# WSBA Report: `{t}`")
    lines.append("")
    lines.append(f"- URL tested: {url}")
    lines.append(f"- Timestamp (UTC): {result['timestamp_utc']}")
    lines.append("")

    lines.append("## DNS Snapshot")
    dns = result.get("dns", {})
    if "error" in dns:
        lines.append(f"- Error: {dns['error']}")
    else:
        for k, v in dns.items():
            lines.append(f"- **{k}**: {', '.join(v) if v else '(none)'}")
    lines.append("")

    lines.append("## HTTP Response")
    http = result.get("http", {})
    if "error" in http:
        lines.append(f"- Error: {http['error']}")
    else:
        lines.append(f"- Status line: {http.get('status_line') or '(unknown)'}")
    lines.append("")

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

    lines.append("## TLS Certificate (Dates/Issuer)")
    tls = result.get("tls", {})
    if "error" in tls:
        lines.append(f"- Error: {tls['error']}")
    else:
        lines.append("```")
        lines.append(tls.get("raw", "").strip() or "(no tls output)")
        lines.append("```")
    lines.append("")

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
    else:
        result["security_headers"] = {"error": "no headers to analyze"}

    result["tls"] = tls_dates(target) if args.scheme == "https" else {"skipped": "http scheme"}

    (outdir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(to_md(result), encoding="utf-8")

    print(f"[+] Wrote: {outdir/'result.json'}")
    print(f"[+] Wrote: {outdir/'report.md'}")


if __name__ == "__main__":
    main()
