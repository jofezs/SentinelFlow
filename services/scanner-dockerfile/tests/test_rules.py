import pytest

from sentinelflow_common.events import Severity
from sentinelflow_dockerfile_scanner.rules import evaluate

HARDENED = """\
FROM python:3.12-slim
RUN useradd --uid 10001 app
USER app
HEALTHCHECK CMD python -c "print('ok')"
CMD ["python", "app.py"]
"""


def _ids(content: str) -> list[str]:
    return [f.rule_id for f in evaluate(content)]


def test_hardened_dockerfile_has_no_findings() -> None:
    assert evaluate(HARDENED) == []


class TestRunAsRoot:
    def test_missing_user(self) -> None:
        findings = [f for f in evaluate("FROM alpine\nCMD sh\n") if f.rule_id == "SF001"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].location == "line 1"

    @pytest.mark.parametrize("user", ["root", "0", "root:root", "0:0"])
    def test_explicit_root(self, user: str) -> None:
        assert "SF001" in _ids(f"FROM alpine\nUSER {user}\n")

    def test_only_final_stage_matters(self) -> None:
        content = "FROM golang AS build\nUSER root\nFROM alpine\nUSER app\nHEALTHCHECK NONE\n"
        assert "SF001" not in _ids(content)
        content = "FROM golang AS build\nUSER app\nFROM alpine\nHEALTHCHECK NONE\n"
        assert "SF001" in _ids(content)

    def test_switching_back_to_root_is_flagged(self) -> None:
        assert "SF001" in _ids("FROM alpine\nUSER app\nRUN x\nUSER root\n")


class TestSecrets:
    @pytest.mark.parametrize(
        "line",
        [
            "ENV DB_PASSWORD=hunter2",
            "ENV API_KEY abc123",
            "ENV FOO=bar AWS_SECRET_ACCESS_KEY=xyz",
            'ENV GITHUB_TOKEN="ghp_example"',
        ],
    )
    def test_secret_in_env_is_critical(self, line: str) -> None:
        findings = [f for f in evaluate(f"FROM alpine\n{line}\n") if f.rule_id == "SF002"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_secret_value_is_not_leaked_into_finding(self) -> None:
        finding = next(
            f for f in evaluate("FROM a\nENV DB_PASSWORD=hunter2\n") if f.rule_id == "SF002"
        )
        assert "hunter2" not in finding.model_dump_json()

    def test_non_secret_env_is_fine(self) -> None:
        assert "SF002" not in _ids("FROM alpine\nENV PATH=/app/bin LANG=C.UTF-8\n")

    def test_empty_secret_env_is_fine(self) -> None:
        assert "SF002" not in _ids('FROM alpine\nENV DB_PASSWORD=""\n')

    def test_arg_with_default_is_critical_without_is_medium(self) -> None:
        with_default = evaluate("FROM alpine\nARG NPM_TOKEN=abc\n")
        without = evaluate("FROM alpine\nARG NPM_TOKEN\n")
        assert next(f for f in with_default if f.rule_id == "SF003").severity == Severity.CRITICAL
        assert next(f for f in without if f.rule_id == "SF003").severity == Severity.MEDIUM


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        ("ADD https://example.com/tool.tar.gz /opt/", "SF004"),
        ("RUN curl -fsSL https://get.example.com | sh", "SF005"),
        ("RUN wget -qO- https://x.io/install | sudo bash", "SF005"),
        ("RUN curl -k https://example.com/file -o f", "SF006"),
        ("RUN curl --insecure https://example.com", "SF006"),
        ("RUN wget --no-check-certificate https://x", "SF006"),
        ("RUN pip install --trusted-host pypi.org flask", "SF006"),
        ("RUN npm config set strict-ssl false", "SF006"),
        ("ENV GIT_SSL_NO_VERIFY=1", "SF006"),
        ("RUN chmod 777 /app", "SF007"),
        ("RUN chmod -R 0777 /data", "SF007"),
        ("RUN chmod a+rwx /tmp/x", "SF007"),
        ("EXPOSE 22", "SF008"),
        ("EXPOSE 8080 22/tcp", "SF008"),
    ],
)
def test_risky_patterns_detected(line: str, rule: str) -> None:
    assert rule in _ids(f"{HARDENED}{line}\n")


@pytest.mark.parametrize(
    "line",
    [
        "ADD --checksum=sha256:abc https://example.com/tool.tar.gz /opt/",
        "ADD ./local.tar.gz /opt/",
        "RUN curl -fsSL https://example.com/script.sh -o script.sh",
        "RUN curl https://example.com | jq .",
        "RUN chmod 755 /app",
        "EXPOSE 2222 8080",
        "RUN echo -k flag-for-other-tool",
    ],
)
def test_safe_patterns_not_flagged(line: str) -> None:
    assert evaluate(f"{HARDENED}{line}\n") == []


def test_missing_healthcheck_is_low() -> None:
    findings = evaluate("FROM alpine\nUSER app\n")
    assert [(f.rule_id, f.severity) for f in findings] == [("SF009", Severity.LOW)]
