# Run with: opa test services/policy-engine/policies -v
package sentinelflow.test.decision

import data.sentinelflow.decision

finding(rule_id, severity) := {
	"rule_id": rule_id,
	"severity": severity,
	"title": rule_id,
	"location": "line 1",
}

scan(target_type, findings, config) := {
	"scan": {"target_type": target_type, "target": "x", "scanner": "test"},
	"findings": findings,
	"config": config,
}

all_policies := {"enabled": null, "params": {}}

policy_ids(result) := {v.policy_id | some v in result.violations}

test_clean_scan_is_allowed if {
	r := decision.result with input as scan("dockerfile", [], all_policies)
	r.allow
	count(r.violations) == 0
	r.evaluated == {"severity_threshold", "no_secrets", "no_root_container", "supply_chain"}
}

test_missing_config_means_all_policies if {
	r := decision.result with input as {"scan": {"target_type": "dockerfile"}, "findings": [finding("SF001", "high")]}
	not r.allow
	"no_root_container" in policy_ids(r)
}

test_insecure_dockerfile_violates_several_policies if {
	findings := [
		finding("SF001", "high"),
		finding("SF002", "critical"),
		finding("SF005", "high"),
		finding("DL3007", "medium"),
	]
	r := decision.result with input as scan("dockerfile", findings, all_policies)
	not r.allow
	policy_ids(r) == {"severity_threshold", "no_secrets", "no_root_container", "supply_chain"}
}

test_disabled_policies_are_skipped if {
	config := {"enabled": ["supply_chain"], "params": {}}
	r := decision.result with input as scan("dockerfile", [finding("SF001", "high")], config)
	r.allow
	r.evaluated == {"supply_chain"}
}

test_policies_only_apply_to_their_target_type if {
	# SF001 on an API endpoint scan cannot trigger the Dockerfile-only root policy.
	r := decision.result with input as scan("api_endpoint", [finding("SF001", "high")], all_policies)
	r.allow
	not "no_root_container" in r.evaluated
}

test_severity_threshold_param if {
	findings := [finding("DL3007", "medium"), finding("API013", "high")]
	default_cfg := decision.result with input as scan("api_endpoint", findings, all_policies)
	default_cfg.allow # default threshold is critical

	strict := {"enabled": null, "params": {"severity_threshold": {"fail_on": "high"}}}
	r := decision.result with input as scan("api_endpoint", findings, strict)
	not r.allow
	some v in r.violations
	v.policy_id == "severity_threshold"
	v.severity == "high"
	v.message == "1 finding(s) at or above 'high' (most severe: high)"
}

test_fixable_vulns_only_counts_fixable if {
	only := {"enabled": ["no_fixable_vulns"], "params": {}}
	fixed := object.union(finding("CVE-2024-0001", "high"), {"fix_available": true})
	unfixed := object.union(finding("CVE-2024-0002", "critical"), {"fix_available": false})

	unfixed_only := decision.result with input as scan("image", [unfixed], only)
	unfixed_only.allow

	r := decision.result with input as scan("image", [fixed, unfixed], only)
	not r.allow
	some v in r.violations
	v.message == "1 fixable vulnerabilit(ies) at or above 'high', e.g. CVE-2024-0001"
}

test_fixable_vulns_min_severity_param if {
	config := {"enabled": ["no_fixable_vulns"], "params": {"no_fixable_vulns": {"min_severity": "critical"}}}
	high_fixed := object.union(finding("CVE-2024-0001", "high"), {"fix_available": true})
	r := decision.result with input as scan("image", [high_fixed], config)
	r.allow
}

test_trivy_secret_findings_count_as_secrets if {
	r := decision.result with input as scan("image", [finding("secret:aws-access-key-id", "critical")], all_policies)
	"no_secrets" in policy_ids(r)
}

test_api_policies if {
	findings := [finding("API001", "high"), finding("API020", "critical"), finding("API023", "low")]
	r := decision.result with input as scan("api_endpoint", findings, all_policies)
	policy_ids(r) == {"https_required", "cors_restricted", "severity_threshold"}
	some v in r.violations
	v.policy_id == "cors_restricted"
	v.severity == "critical"
	v.message == "Permissive CORS: API020 (line 1)"
}

test_plain_wildcard_cors_is_allowed if {
	r := decision.result with input as scan("api_endpoint", [finding("API023", "low")], all_policies)
	r.allow
}

test_hsts_required if {
	r := decision.result with input as scan("api_endpoint", [finding("API010", "medium")], all_policies)
	policy_ids(r) == {"hsts_required"}
}

test_missing_location_is_rendered_as_dash if {
	f := {"rule_id": "SF001", "severity": "high", "title": "t", "location": null}
	r := decision.result with input as scan("dockerfile", [f], {"enabled": ["no_root_container"]})
	some v in r.violations
	v.message == "Container runs as root: SF001 (-)"
}
