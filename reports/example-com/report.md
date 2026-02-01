# WSBA Report: `example.com`

- URL tested: https://example.com/
- Timestamp (UTC): 2026-02-01T20:15:43+00:00

## Score
- **Score:** 30/100
- **Grade:** F
- **Level:** poor

## Executive Summary
Top findings based on missing security headers (non-intrusive baseline):

- **[Medium]** Missing Strict-Transport-Security
- **[Medium]** Missing Content-Security-Policy
- **[Low]** Missing X-Frame-Options

## Recommended Header Set (Starting Point)
Validate these against application requirements before deployment:

- **Strict-Transport-Security**: `max-age=15552000; includeSubDomains; preload`
- **Content-Security-Policy**: start minimal (consider Report-Only), then tighten.
- **X-Frame-Options**: `DENY`
- **X-Content-Type-Options**: `nosniff`
- **Referrer-Policy**: `strict-origin-when-cross-origin`
- **Permissions-Policy**: `camera=(), microphone=(), geolocation=()`

## DNS Snapshot
- **A**: 104.18.26.120, 104.18.27.120
- **AAAA**: 2606:4700::6812:1b78, 2606:4700::6812:1a78
- **MX**: 0 .
- **TXT**: "v=spf1 -all", "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"

## HTTP Response
- Status line: HTTP/2 200 

## Security Headers

### Missing / Not Observed
- **Strict-Transport-Security**
- **Content-Security-Policy**
- **X-Frame-Options**
- **X-Content-Type-Options**
- **Referrer-Policy**
- **Permissions-Policy**

## TLS Certificate (Dates/Issuer)
```
subject=CN=example.com
issuer=C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
notBefore=Dec 16 19:39:32 2025 GMT
notAfter=Mar 16 18:32:44 2026 GMT
```

## Notes
- Non-intrusive baseline audit. No exploitation performed.
