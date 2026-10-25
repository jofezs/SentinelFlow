# Shared helpers for SentinelFlow policies.
package sentinelflow.lib

severity_rank := {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

rank_to_severity := {rank: name | some name, rank in severity_rank}

at_least(severity, minimum) if severity_rank[severity] >= severity_rank[minimum]

# A policy parameter from the project's config, or the default.
param(policy, name, default_value) := object.get(input, ["config", "params", policy, name], default_value)

# Findings whose rule_id is in `ids`.
matching(ids) := [f | some f in input.findings; f.rule_id in ids]

max_severity(findings) := rank_to_severity[max({severity_rank[f.severity] | some f in findings})]

location(f) := f.location if f.location != null

else := "-"

# "SF001 (line 1), SF005 (line 3)" - stable order for readable messages.
summary(findings) := concat(", ", sort({sprintf("%s (%s)", [f.rule_id, location(f)]) | some f in findings}))
