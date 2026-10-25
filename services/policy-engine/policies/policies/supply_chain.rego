package sentinelflow.policies.supply_chain

import data.sentinelflow.lib

applies_to := {"dockerfile"}

# SF004 remote ADD, SF005 curl | sh, SF006 TLS verification disabled.
violations contains violation if {
	risky := lib.matching({"SF004", "SF005", "SF006"})
	count(risky) > 0
	violation := {
		"message": sprintf("Unverified downloads: %s", [lib.summary(risky)]),
		"severity": lib.max_severity(risky),
	}
}
