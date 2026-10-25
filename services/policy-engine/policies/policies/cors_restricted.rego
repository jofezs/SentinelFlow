package sentinelflow.policies.cors_restricted

import data.sentinelflow.lib

applies_to := {"api_endpoint"}

# API020 reflected origin, API021 null origin, API022 wildcard with credentials.
# API023 (plain wildcard) is allowed: it is legitimate for public APIs.
violations contains violation if {
	cors := lib.matching({"API020", "API021", "API022"})
	count(cors) > 0
	violation := {
		"message": sprintf("Permissive CORS: %s", [lib.summary(cors)]),
		"severity": lib.max_severity(cors),
	}
}
