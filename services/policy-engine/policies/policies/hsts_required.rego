package sentinelflow.policies.hsts_required

import data.sentinelflow.lib

applies_to := {"api_endpoint"}

violations contains violation if {
	count(lib.matching({"API010"})) > 0
	violation := {
		"message": "Strict-Transport-Security header is missing",
		"severity": "medium",
	}
}
