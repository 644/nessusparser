from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Oracle TNS Listener Remote Poisoning']
	name='Oracle TNS Listener Poisoning'
	description="The Oracle TNS listener service listening on a number of hosts as part of their underlying Oracle Database deployments may be vulnerable to a man-in-the-middle attack. As Oracle Database deployments are typically used to store large volumes of data for processing and presentation by applications, some of which may handle sensitive data, this issue could present a significant threat to the security of the affected databases and the data housed within them."
	risk_description="A number of Oracle Database server deployments appear to present TNS listener services which allow service registration from a remote host. Commonly referred to as the \"TNS Poison\" vulnerability, this issue could permit a suitably positioned attacker to route some TNS listener traffic through a malicious/compromised host, which could allow for session hijacking of a database connection or denial-of-service attacks against each host and the listener service. Such activity could enable the compromise of the data hosted within the Oracle Database deployments or facilitate the compromise of the underlying host. These attacks would be difficult to detect, as all incoming connections would appear to be from authorised hosts/users.\n\nThis issue is known to affect versions of Oracle Database from 8i to 11g. More recent releases, such as 12c, have had this issue addressed."
	recommendation="Sources indicate that Oracle have provided workarounds to customers with existing support contracts to address this issue, either in the form of a patch or reconfiguration of the service.\n\nIt is recommended that a review of the references included within the Notes section be undertaken and any relevant workarounds be applied to each affected deployment. This activity should only be undertaken after significant research and review has been undertaken to ensure that such actions will not have a detrimental impact on the hosts or services.\n\nIf no suitable workarounds are available for a deployment, it will likely require an upgrade of the underlying Oracle software.\n\nAccess to these listener services could be restricted through segregation in order to minimise their exposure to scrutiny from other network assets."
	notes="<url>http://www.oracle.com/technetwork/topics/security/alert-cve-2012-1675-1608180.html</url>\n<url>https://forums.oracle.com/thread/2385622</url>\n<url>http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1675</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices