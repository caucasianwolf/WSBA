# WSBA — Web Security Baseline Audit

WSBA is a lightweight, ethical web security baseline auditing tool designed to evaluate common security hardening controls without intrusive testing.

This project demonstrates a practical cybersecurity analyst workflow: tooling, evidence collection, and professional reporting.

---

## What WSBA Checks (Non-Intrusive)

- DNS records (A, AAAA, MX, TXT)
- HTTP response status
- Common HTTP security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- TLS certificate subject, issuer, and validity dates

No exploitation, brute-force attacks, authentication testing, or aggressive scanning is performed.

---

## Why This Project Exists

Many real-world security analyst roles involve:
- reviewing configurations
- validating baseline security posture
- producing clear, actionable reports

WSBA focuses on defensive security, ethical assessment, and clear documentation rather than exploitation.

---

## How to Run

From the project root directory:

```bash
python3 src/wsba.py --target example.com --out reports/example-com

## AUTHOR ##

Archil Veltauri
IBM Certified Cybersecurity Analyst

## Project Status ##g
WSBA is a completed baseline security assessment tool intended for educational and portfolio use.  
All scans are non-intrusive and must be run only against owned or explicitly authorized targets.
