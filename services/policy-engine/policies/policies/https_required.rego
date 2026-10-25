package sentinelflow.policies.https_required

import data.sentinelflow.lib

applies_to := {"api_endpoint"}

# API001 plaintext HTTP, API002 weak TLS, API003 invalid certificate.
violations contains violation if {
	transport := lib.matching({"API001", "API002", "API003"})
	count(transport) > 0
	violation := {
		"message": sprintf("Insecure transport: %s", [lib.summary(transport)]),
		"severity": "high",
	}
}
