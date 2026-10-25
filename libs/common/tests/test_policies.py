import pytest
from pydantic import ValidationError

from sentinelflow_common.events import PolicyConfig, Severity
from sentinelflow_common.policies import POLICIES, validate_config


def test_defaults_mean_all_policies() -> None:
    assert validate_config(None, {}) == PolicyConfig(enabled=None, params={})


def test_params_are_validated_and_normalized() -> None:
    config = validate_config(
        ["severity_threshold", "no_secrets", "no_secrets"],
        {"severity_threshold": {"fail_on": "high"}, "no_fixable_vulns": {}},
    )
    assert config.enabled == ("severity_threshold", "no_secrets")  # deduplicated
    assert config.params == {
        "severity_threshold": {"fail_on": "high"},
        "no_fixable_vulns": {"min_severity": "high"},  # default filled in
    }


@pytest.mark.parametrize(
    ("enabled", "params", "message"),
    [
        (["does_not_exist"], {}, "unknown policies"),
        (None, {"nope": {}}, "unknown policy in params"),
        (None, {"no_secrets": {"x": 1}}, "takes no parameters"),
    ],
)
def test_invalid_config_rejected(
    enabled: list[str] | None, params: dict[str, dict[str, object]], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_config(enabled, params)


@pytest.mark.parametrize(
    "params",
    [{"fail_on": "catastrophic"}, {"fail_on": "high", "extra": True}],
)
def test_bad_param_values_rejected(params: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        validate_config(None, {"severity_threshold": params})


def test_catalog_ids_are_rego_safe_identifiers() -> None:
    for policy_id in POLICIES:
        assert policy_id.isidentifier(), policy_id
    assert Severity.CRITICAL.value == "critical"
