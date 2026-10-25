package sentinelflow.policies.no_secrets

import data.sentinelflow.lib

applies_to := {"image", "dockerfile"}

# SF002/SF003: secrets in Dockerfile ENV/ARG. secret:*: Trivy secret scanning.
is_secret(rule_id) if rule_id in {"SF002", "SF003"}

is_secret(rule_id) if startswith(rule_id, "secret:")

secrets := [f | some f in input.findings; is_secret(f.rule_id)]

violations contains violation if {
	count(secrets) > 0
	violation := {
		"message": sprintf("Embedded secrets: %s", [lib.summary(secrets)]),
		"severity": "critical",
	}
}
