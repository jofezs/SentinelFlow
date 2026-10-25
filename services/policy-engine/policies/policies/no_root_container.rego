package sentinelflow.policies.no_root_container

import data.sentinelflow.lib

applies_to := {"dockerfile"}

violations contains violation if {
	root := lib.matching({"SF001"})
	count(root) > 0
	violation := {
		"message": sprintf("Container runs as root: %s", [lib.summary(root)]),
		"severity": "high",
	}
}
