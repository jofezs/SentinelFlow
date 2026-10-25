"""SentinelFlow security rules (SFxxx) for Dockerfiles.

These complement Hadolint (which focuses on build best practices) with checks
aimed at security posture. Rule IDs are stable so policies can reference them.
"""

import re
import shlex
from collections.abc import Callable

from sentinelflow_common.events import Finding, Severity
from sentinelflow_dockerfile_scanner.parser import Instruction, final_stage, parse

Rule = Callable[[list[Instruction]], list[Finding]]

_SECRET_NAME = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credentials?)",
    re.IGNORECASE,
)
_PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b")
_WORLD_WRITABLE = re.compile(r"\bchmod\s+(-\S+\s+)*(0?777|a\+rwx|o\+w)\b")
_TLS_DISABLED = re.compile(
    r"(\bcurl\b[^;&|]*\s(-k|--insecure)\b"
    r"|--no-check-certificate"
    r"|--trusted-host"
    r"|strict-ssl\s+false"
    r"|GIT_SSL_NO_VERIFY"
    r"|sslverify\s*=?\s*(false|0))",
    re.IGNORECASE,
)


def _at(ins: Instruction) -> str:
    return f"line {ins.line}"


def _split(args: str) -> list[str]:
    try:
        return shlex.split(args)
    except ValueError:
        return args.split()


def run_as_root(instructions: list[Instruction]) -> list[Finding]:
    stage = final_stage(instructions)
    users = [i for i in stage if i.keyword == "USER"]
    remediation = "Create an unprivileged user and add `USER <name>` before the final CMD."
    if not users:
        anchor = stage[0] if stage else None
        return [
            Finding(
                rule_id="SF001",
                title="Container runs as root (no USER instruction)",
                severity=Severity.HIGH,
                description="Without USER the process runs as UID 0, so a container escape "
                "or RCE gains root privileges.",
                location=_at(anchor) if anchor else None,
                remediation=remediation,
            )
        ]
    last = users[-1]
    if last.args.split(":")[0].strip() in {"root", "0"}:
        return [
            Finding(
                rule_id="SF001",
                title="Container explicitly runs as root",
                severity=Severity.HIGH,
                location=_at(last),
                remediation=remediation,
            )
        ]
    return []


def _env_pairs(args: str) -> list[tuple[str, str]]:
    tokens = _split(args)
    if any("=" in t for t in tokens):
        return [(k, v) for k, _, v in (t.partition("=") for t in tokens)]
    return [(tokens[0], " ".join(tokens[1:]))] if tokens else []


def secrets_in_build(instructions: list[Instruction]) -> list[Finding]:
    findings = []
    for ins in instructions:
        if ins.keyword == "ENV":
            for name, value in _env_pairs(ins.args):
                if _SECRET_NAME.search(name) and value:
                    findings.append(
                        Finding(
                            rule_id="SF002",
                            title=f"Secret '{name}' hard-coded in ENV",
                            severity=Severity.CRITICAL,
                            description="ENV values are stored in the image config and visible "
                            "to anyone who can pull the image (docker inspect).",
                            location=_at(ins),
                            remediation="Inject secrets at runtime (Kubernetes Secrets, "
                            "a vault) instead of baking them into the image.",
                        )
                    )
        elif ins.keyword == "ARG":
            name, has_default, default = ins.args.partition("=")
            if not _SECRET_NAME.search(name):
                continue
            findings.append(
                Finding(
                    rule_id="SF003",
                    title=f"Secret '{name.strip()}' passed as build ARG",
                    severity=Severity.CRITICAL if has_default and default else Severity.MEDIUM,
                    description="Build args are recorded in image history (docker history).",
                    location=_at(ins),
                    remediation="Use BuildKit secret mounts: RUN --mount=type=secret,id=...",
                )
            )
    return findings


def remote_add(instructions: list[Instruction]) -> list[Finding]:
    return [
        Finding(
            rule_id="SF004",
            title="ADD fetches a remote URL without integrity verification",
            severity=Severity.MEDIUM,
            location=_at(ins),
            remediation="Download with curl and verify a pinned checksum, or use ADD --checksum.",
        )
        for ins in instructions
        if ins.keyword == "ADD"
        and "--checksum" not in ins.args
        and any(t.startswith(("http://", "https://")) for t in _split(ins.args))
    ]


def pipe_to_shell(instructions: list[Instruction]) -> list[Finding]:
    return [
        Finding(
            rule_id="SF005",
            title="Remote script piped directly into a shell",
            severity=Severity.HIGH,
            description="curl | sh executes whatever the server returns, with no integrity "
            "check - a supply-chain compromise vector.",
            location=_at(ins),
            remediation="Download the script, verify its checksum or signature, then run it.",
        )
        for ins in instructions
        if ins.keyword == "RUN" and _PIPE_TO_SHELL.search(ins.args)
    ]


def tls_verification_disabled(instructions: list[Instruction]) -> list[Finding]:
    return [
        Finding(
            rule_id="SF006",
            title="TLS certificate verification disabled",
            severity=Severity.HIGH,
            description="Downloads made without certificate verification can be "
            "tampered with in transit (MITM).",
            location=_at(ins),
            remediation="Remove the insecure flag and install the required CA certificates.",
        )
        for ins in instructions
        if ins.keyword in {"RUN", "ENV"} and _TLS_DISABLED.search(ins.args)
    ]


def world_writable(instructions: list[Instruction]) -> list[Finding]:
    return [
        Finding(
            rule_id="SF007",
            title="World-writable permissions (chmod 777)",
            severity=Severity.MEDIUM,
            location=_at(ins),
            remediation="Grant the minimum permissions needed, owned by the runtime user.",
        )
        for ins in instructions
        if ins.keyword == "RUN" and _WORLD_WRITABLE.search(ins.args)
    ]


def ssh_exposed(instructions: list[Instruction]) -> list[Finding]:
    return [
        Finding(
            rule_id="SF008",
            title="SSH port 22 exposed",
            severity=Severity.MEDIUM,
            description="Running sshd in a container widens the attack surface; "
            "use `kubectl exec` / `docker exec` for access.",
            location=_at(ins),
        )
        for ins in instructions
        if ins.keyword == "EXPOSE" and any(p.split("/")[0] == "22" for p in ins.args.split())
    ]


def missing_healthcheck(instructions: list[Instruction]) -> list[Finding]:
    stage = final_stage(instructions)
    if not stage or any(i.keyword == "HEALTHCHECK" for i in stage):
        return []
    return [
        Finding(
            rule_id="SF009",
            title="No HEALTHCHECK defined",
            severity=Severity.LOW,
            location=_at(stage[0]),
            remediation="Add a HEALTHCHECK (or rely on Kubernetes liveness/readiness probes).",
        )
    ]


RULES: tuple[Rule, ...] = (
    run_as_root,
    secrets_in_build,
    remote_add,
    pipe_to_shell,
    tls_verification_disabled,
    world_writable,
    ssh_exposed,
    missing_healthcheck,
)


def evaluate(content: str) -> list[Finding]:
    instructions = parse(content)
    return [finding for rule in RULES for finding in rule(instructions)]
