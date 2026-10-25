package sentinelflow.policies.no_fixable_vulns

import data.sentinelflow.lib

applies_to := {"image"}

min_severity := lib.param("no_fixable_vulns", "min_severity", "high")

fixable := [f |
	some f in input.findings
	f.fix_available == true
	lib.at_least(f.severity, min_severity)
]

violations contains violation if {
	count(fixable) > 0
	ids := sort({f.rule_id | some f in fixable})
	violation := {
		"message": sprintf(
			"%d fixable vulnerabilit(ies) at or above '%s', e.g. %s",
			[count(ids), min_severity, concat(", ", array.slice(ids, 0, 3))],
		),
		"severity": lib.max_severity(fixable),
	}
}
