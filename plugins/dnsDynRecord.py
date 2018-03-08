from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=[35372]
	name="DNS Dynamic Updates"
	description="DNS services were identified which permit their records for specific zones to be dynamically updated. This can be used to facilitate man-in-the-middle attacks."
	risk_description="DNS services were found to permit the dynamic updating of their records. This functionality can be used to create or alter DNS records, enabling an attacker to redirect traffic away from a legitimate host to one under their control. This could be used to intercept sensitive service traffic or direct users to malicious resources/applications, through which an attacker may attempt to compromise user hosts or account credentials.\n\nIt should be noted that this finding can reflect a legitimate configuration if testing of these services was conducted from within a network subnet which is required to perform dynamic updates by the DNS services."
	recommendation="Limit the sources addresses that are allowed to perform dynamic updates against these services (e.g. with BIND's 'allow-update' option) or implement the signing of DNS traffic (e.g. TSIG or SIG(0))."
	notes="<url>https://technet.microsoft.com/en-us/library/cc753751(v=ws.11).aspx</url>"
	notes+="\n<url>https://technet.microsoft.com/en-us/library/cc725703(v=ws.11).aspx</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices