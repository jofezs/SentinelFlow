"""Runs Trivy against a remote image and maps its JSON report to Findings."""

import asyncio
import json
from typing import Any

from sentinelflow_common.events import Finding, Severity

SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class TrivyError(RuntimeError):
    pass


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _vulnerability(target: str, v: dict[str, Any]) -> Finding:
    pkg, version, fixed = (
        v.get("PkgName", "?"),
        v.get("InstalledVersion", "?"),
        v.get("FixedVersion"),
    )
    return Finding(
        rule_id=v["VulnerabilityID"],
        title=_clip(f"{pkg} {version}: {v.get('Title') or v['VulnerabilityID']}", 200),
        severity=SEVERITY.get(v.get("Severity", ""), Severity.INFO),
        description=_clip(v.get("Description", ""), 500),
        location=_clip(f"{target} > {pkg}@{version}", 300),
        remediation=f"Upgrade {pkg} to {fixed}" if fixed else "No fixed version available yet",
    )


def _secret(target: str, s: dict[str, Any]) -> Finding:
    # Trivy's "Match" field is deliberately not copied: it contains (redacted) secret context.
    return Finding(
        rule_id=f"secret:{s.get('RuleID', 'unknown')}",
        title=f"Secret found in image: {s.get('Title', 'unknown')}",
        severity=SEVERITY.get(s.get("Severity", ""), Severity.HIGH),
        location=f"{target}:{s.get('StartLine', '?')}",
        remediation="Remove the secret from the image, rebuild, and rotate the credential.",
    )


def parse_report(raw: bytes | str) -> list[Finding]:
    report = json.loads(raw)
    findings: dict[tuple[str, ...], Finding] = {}
    key: tuple[str, ...]
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            # The same CVE can be reported for one package via several targets.
            key = (v["VulnerabilityID"], v.get("PkgName", ""), v.get("InstalledVersion", ""))
            findings.setdefault(key, _vulnerability(target, v))
        for s in result.get("Secrets") or []:
            key = ("secret", s.get("RuleID", ""), target, str(s.get("StartLine")))
            findings.setdefault(key, _secret(target, s))
    return list(findings.values())


async def run(image: str, binary: str, timeout: float, cache_dir: str) -> list[Finding]:
    """Scan ``image`` from its registry (no Docker daemon or socket needed)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            "image",
            "--quiet",
            "--format",
            "json",
            "--scanners",
            "vuln,secret",
            "--timeout",
            f"{int(timeout)}s",
            "--cache-dir",
            cache_dir,
            "--",  # everything after is the image reference, never a flag
            image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise TrivyError(f"trivy binary not found: {binary}") from exc

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout + 30)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise TrivyError(f"trivy timed out after {timeout}s") from exc

    if proc.returncode != 0:
        message = stderr.decode(errors="replace").strip().splitlines()
        raise TrivyError(_clip(f"trivy failed: {message[-1] if message else proc.returncode}", 500))
    try:
        return parse_report(stdout)
    except (json.JSONDecodeError, KeyError) as exc:
        raise TrivyError("could not parse trivy report") from exc
