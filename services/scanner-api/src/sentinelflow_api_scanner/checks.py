"""Pure security checks over a ProbeResult (no I/O, fully unit-testable).

Rule IDs:
  API001 plaintext HTTP          API010 missing HSTS          API016 insecure cookie
  API002 weak TLS version        API011 weak HSTS max-age     API020 CORS origin reflection
  API003 invalid certificate     API012 missing CSP           API021 CORS allows 'null'
  API004 certificate expiring    API013 missing nosniff       API022 CORS * with credentials
                                 API014 clickjacking          API023 CORS allows any origin
                                 API015 version disclosure
"""

import re
from datetime import datetime
from urllib.parse import urlsplit

import httpx

from sentinelflow_api_scanner.probe import PROBE_ORIGIN, ProbeResult, TlsInfo
from sentinelflow_common.events import Finding, Severity

WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
HSTS_MIN_MAX_AGE = 180 * 24 * 3600
_HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def _finding(rule_id: str, title: str, severity: Severity, **kwargs: str | None) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, **kwargs)


def check_transport(result: ProbeResult) -> list[Finding]:
    if urlsplit(result.final_url).scheme != "http":
        return []
    return [
        _finding(
            "API001",
            "Endpoint is served over plaintext HTTP",
            Severity.HIGH,
            description="Requests and responses (including credentials) can be read and "
            "modified in transit.",
            location=result.final_url,
            remediation="Serve over HTTPS and redirect all HTTP traffic to HTTPS.",
        )
    ]


def check_tls(tls: TlsInfo | None, now: datetime) -> list[Finding]:
    if tls is None:
        return []
    findings = []
    if tls.version in WEAK_TLS:
        findings.append(
            _finding(
                "API002",
                f"Weak TLS version negotiated: {tls.version}",
                Severity.HIGH,
                remediation="Require TLS 1.2 or newer.",
            )
        )
    if tls.cert_error:
        findings.append(
            _finding(
                "API003",
                "TLS certificate failed verification",
                Severity.HIGH,
                description=tls.cert_error,
                remediation="Use a certificate from a trusted CA that matches the hostname.",
            )
        )
    elif tls.not_after is not None:
        days_left = (tls.not_after - now).days
        if days_left < 30:
            findings.append(
                _finding(
                    "API004",
                    f"TLS certificate expires in {days_left} days",
                    Severity.HIGH if days_left < 14 else Severity.MEDIUM,
                    remediation="Renew the certificate and automate renewal (e.g. ACME).",
                )
            )
    return findings


def check_security_headers(headers: httpx.Headers, https: bool) -> list[Finding]:
    findings = []
    if https:
        hsts = headers.get("strict-transport-security")
        if hsts is None:
            findings.append(
                _finding(
                    "API010",
                    "Missing Strict-Transport-Security header",
                    Severity.MEDIUM,
                    description="Without HSTS, a network attacker can downgrade the first "
                    "request to HTTP (SSL stripping).",
                    remediation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                )
            )
        else:
            match = _HSTS_MAX_AGE.search(hsts)
            if not match or int(match.group(1)) < HSTS_MIN_MAX_AGE:
                findings.append(
                    _finding(
                        "API011",
                        "HSTS max-age is shorter than 180 days",
                        Severity.LOW,
                        location=f"Strict-Transport-Security: {hsts[:100]}",
                    )
                )
    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append(_finding("API012", "Missing Content-Security-Policy header", Severity.LOW))
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        findings.append(
            _finding(
                "API013",
                "Missing X-Content-Type-Options: nosniff",
                Severity.LOW,
                remediation="X-Content-Type-Options: nosniff",
            )
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                "API014",
                "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
                Severity.LOW,
                remediation="Content-Security-Policy: frame-ancestors 'none'",
            )
        )
    return findings


def check_disclosure(headers: httpx.Headers) -> list[Finding]:
    return [
        _finding(
            "API015",
            f"{name} header discloses software version",
            Severity.LOW,
            location=f"{name}: {headers[name][:80]}",
            remediation="Remove version details from response headers.",
        )
        for name in _DISCLOSURE_HEADERS
        if re.search(r"\d", headers.get(name, ""))
    ]


def check_cookies(headers: httpx.Headers) -> list[Finding]:
    findings = []
    for raw in headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        attributes = {part.strip().split("=", 1)[0].lower() for part in raw.split(";")[1:]}
        missing = [a for a in ("Secure", "HttpOnly", "SameSite") if a.lower() not in attributes]
        if missing:
            findings.append(
                _finding(
                    "API016",
                    f"Cookie '{name}' is missing {', '.join(missing)}",
                    Severity.MEDIUM if "Secure" in missing else Severity.LOW,
                    remediation="Set-Cookie: <name>=<value>; Secure; HttpOnly; SameSite=Lax",
                )
            )
    return findings


def check_cors(headers: httpx.Headers, probe_origin: str = PROBE_ORIGIN) -> list[Finding]:
    allowed = headers.get("access-control-allow-origin")
    if allowed is None:
        return []
    allowed = allowed.strip()
    credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if allowed == probe_origin:
        return [
            _finding(
                "API020",
                "CORS reflects arbitrary Origin"
                + (" with credentials allowed" if credentials else ""),
                Severity.CRITICAL if credentials else Severity.HIGH,
                description="Any website can make cross-origin requests to this API"
                + (" and read authenticated responses." if credentials else "."),
                remediation="Validate Origin against an explicit allowlist.",
            )
        ]
    if allowed == "null":
        return [
            _finding(
                "API021",
                "CORS allows the 'null' origin",
                Severity.HIGH if credentials else Severity.MEDIUM,
                description="Sandboxed iframes and local files send Origin: null.",
            )
        ]
    if allowed == "*":
        if credentials:
            return [_finding("API022", "CORS wildcard combined with credentials", Severity.HIGH)]
        return [
            _finding(
                "API023",
                "CORS allows any origin (*)",
                Severity.LOW,
                description="Acceptable for fully public APIs; otherwise restrict origins.",
            )
        ]
    return []


def evaluate(result: ProbeResult, now: datetime) -> list[Finding]:
    https = urlsplit(result.final_url).scheme == "https"
    return [
        *check_transport(result),
        *check_tls(result.tls, now),
        *check_security_headers(result.headers, https),
        *check_disclosure(result.headers),
        *check_cookies(result.headers),
        *check_cors(result.headers),
    ]
