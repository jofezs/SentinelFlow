from datetime import UTC, datetime, timedelta

import httpx
import pytest

from sentinelflow_api_scanner import checks
from sentinelflow_api_scanner.probe import PROBE_ORIGIN, ProbeResult, TlsInfo
from sentinelflow_common.events import Severity

NOW = datetime(2026, 10, 25, tzinfo=UTC)
SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
}


def _result(
    url: str = "https://api.example.com/", headers: object = None, **kw: object
) -> ProbeResult:
    return ProbeResult(
        requested_url=url,
        final_url=url,
        status_code=200,
        headers=httpx.Headers(headers if headers is not None else SECURE_HEADERS),  # type: ignore[arg-type]
        tls=kw.get("tls", TlsInfo(version="TLSv1.3", not_after=NOW + timedelta(days=90))),  # type: ignore[arg-type]
    )


def _ids(findings: list) -> list[str]:  # type: ignore[type-arg]
    return [f.rule_id for f in findings]


def test_hardened_endpoint_has_no_findings() -> None:
    assert checks.evaluate(_result(), NOW) == []


def test_plaintext_http() -> None:
    findings = checks.evaluate(_result("http://api.example.com/", tls=None), NOW)
    assert "API001" in _ids(findings)
    assert "API010" not in _ids(findings)  # HSTS only applies to HTTPS


@pytest.mark.parametrize(
    ("tls", "expected"),
    [
        (TlsInfo(version="TLSv1.1", not_after=NOW + timedelta(days=90)), [("API002", "high")]),
        (TlsInfo(version="TLSv1.2", cert_error="self-signed certificate"), [("API003", "high")]),
        (TlsInfo(version="TLSv1.3", not_after=NOW + timedelta(days=20)), [("API004", "medium")]),
        (TlsInfo(version="TLSv1.3", not_after=NOW + timedelta(days=5)), [("API004", "high")]),
        (TlsInfo(version="TLSv1.2", not_after=NOW + timedelta(days=365)), []),
    ],
)
def test_tls_checks(tls: TlsInfo, expected: list[tuple[str, str]]) -> None:
    assert [(f.rule_id, f.severity.value) for f in checks.check_tls(tls, NOW)] == expected


def test_missing_security_headers() -> None:
    findings = checks.check_security_headers(httpx.Headers({}), https=True)
    assert _ids(findings) == ["API010", "API012", "API013", "API014"]


def test_short_hsts_and_x_frame_options_alternative() -> None:
    headers = httpx.Headers(
        {
            "Strict-Transport-Security": "max-age=300",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
    )
    assert _ids(checks.check_security_headers(headers, https=True)) == ["API011"]


def test_version_disclosure() -> None:
    headers = httpx.Headers({"Server": "nginx/1.18.0", "X-Powered-By": "Express"})
    findings = checks.check_disclosure(headers)
    assert len(findings) == 1
    assert findings[0].location == "server: nginx/1.18.0"


def test_cookie_flags() -> None:
    headers = httpx.Headers(
        [
            ("Set-Cookie", "session=abc123; Path=/"),
            ("Set-Cookie", "prefs=dark; Secure; SameSite=Lax"),
            ("Set-Cookie", "ok=1; Secure; HttpOnly; SameSite=Strict"),
        ]
    )
    findings = checks.check_cookies(headers)
    assert [(f.title, f.severity) for f in findings] == [
        ("Cookie 'session' is missing Secure, HttpOnly, SameSite", Severity.MEDIUM),
        ("Cookie 'prefs' is missing HttpOnly", Severity.LOW),
    ]
    assert "abc123" not in findings[0].model_dump_json()


@pytest.mark.parametrize(
    ("acao", "credentials", "expected"),
    [
        (PROBE_ORIGIN, "true", ("API020", Severity.CRITICAL)),
        (PROBE_ORIGIN, None, ("API020", Severity.HIGH)),
        ("null", None, ("API021", Severity.MEDIUM)),
        ("*", "true", ("API022", Severity.HIGH)),
        ("*", None, ("API023", Severity.LOW)),
    ],
)
def test_cors(acao: str, credentials: str | None, expected: tuple[str, Severity]) -> None:
    headers = {"Access-Control-Allow-Origin": acao}
    if credentials:
        headers["Access-Control-Allow-Credentials"] = credentials
    findings = checks.check_cors(httpx.Headers(headers))
    assert [(f.rule_id, f.severity) for f in findings] == [expected]


def test_cors_explicit_origin_is_fine() -> None:
    headers = httpx.Headers({"Access-Control-Allow-Origin": "https://app.example.com"})
    assert checks.check_cors(headers) == []
