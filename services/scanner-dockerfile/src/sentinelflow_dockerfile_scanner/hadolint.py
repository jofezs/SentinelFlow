"""Runs the Hadolint binary as a subprocess and maps its output to Findings."""

import asyncio
import json

from sentinelflow_common.events import Finding, Severity

LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}


class HadolintError(RuntimeError):
    pass


def _docs_url(code: str) -> str:
    if code.startswith("SC"):
        return f"https://www.shellcheck.net/wiki/{code}"
    return f"https://github.com/hadolint/hadolint/wiki/{code}"


def parse_output(raw: bytes | str) -> list[Finding]:
    items = json.loads(raw or "[]")
    return [
        Finding(
            rule_id=item["code"],
            title=item["message"],
            severity=LEVEL_TO_SEVERITY.get(item.get("level", ""), Severity.INFO),
            location=f"line {item['line']}",
            remediation=_docs_url(item["code"]),
        )
        for item in items
    ]


async def run(content: str, binary: str = "hadolint", timeout: float = 30.0) -> list[Finding]:
    """Lint Dockerfile content passed on stdin.

    Executed without a shell, and the content never touches disk, so untrusted
    Dockerfiles cannot inject commands or paths.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            "--format",
            "json",
            "--no-fail",
            "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise HadolintError(f"hadolint binary not found: {binary}") from exc

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(content.encode()), timeout)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise HadolintError(f"hadolint timed out after {timeout}s") from exc

    if proc.returncode != 0:
        raise HadolintError(f"hadolint exited {proc.returncode}: {stderr.decode()[:500]}")
    try:
        return parse_output(stdout)
    except (json.JSONDecodeError, KeyError) as exc:
        raise HadolintError("could not parse hadolint output") from exc
