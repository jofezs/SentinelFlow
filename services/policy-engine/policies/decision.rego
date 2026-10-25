# Entry point: POST /v1/data/sentinelflow/decision/result
#
# input:
#   scan:     {target_type, target, scanner}
#   findings: [{rule_id, severity, title, location, fix_available, ...}]
#   config:   {enabled: [policy_id] | null (null = all), params: {policy_id: {...}}}
package sentinelflow.decision

all_enabled if object.get(input, ["config", "enabled"], null) == null

enabled(_) if all_enabled

enabled(name) if name in input.config.enabled

# Policies that were enabled AND apply to this target type.
evaluated contains name if {
	some name, policy in data.sentinelflow.policies
	enabled(name)
	input.scan.target_type in policy.applies_to
}

violations contains violation if {
	some name in evaluated
	some v in data.sentinelflow.policies[name].violations
	violation := object.union(v, {"policy_id": name})
}

default allow := false

allow if count(violations) == 0

result := {
	"allow": allow,
	"violations": violations,
	"evaluated": evaluated,
}
