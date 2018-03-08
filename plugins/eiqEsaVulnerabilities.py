from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=[22127]
	name="eIQnetworks Enterprise Security Analyzer"
	description="A security event/logging analysis application is installed on at least one host that is vulnerable to remote buffer overflow attacks."
	risk_description="Variants of the eIQnetworks Enterprise/Network Security Analyzer software installed on hosts is known to be affected by multiple stack-based buffer overflows in the Syslog service. Using a long argument to any of several commands, an unauthenticated, remote attacker may be able to leverage this issue to execute arbitrary code on the affected host with LOCAL SYSTEM privileges, leading to its complete compromise. If the underlying host is a domain member, this could provide attackers with additional resources through which other domain resources can be compromised.\n\nIt should be noted that exploits for these issues are publicly available."
	recommendation="This issue has been addressed in more recent releases of the Enterprise/Network Security Analyzer software (2.1.14 and 4.5.4). Affected deployments should be brought into line with the most recent, supported release or decommissioned."
	notes="<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2006-3838</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices