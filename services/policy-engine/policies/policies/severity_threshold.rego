package sentinelflow.policies.severity_threshold

import data.sentinelflow.lib

applies_to := {"image", "dockerfile", "api_endpoint"}

threshold := lib.param("severity_threshold", "fail_on", "critical")

offending := [f | some f in input.findings; lib.at_least(f.severity, threshold)]

violations contains violation if {
	count(offending) > 0
	most_severe := lib.max_severity(offending)
	violation := {
		"message": sprintf(
			"%d finding(s) at or above '%s' (most severe: %s)",
			[count(offending), threshold, most_severe],
		),
		"severity": most_severe,
	}
}
