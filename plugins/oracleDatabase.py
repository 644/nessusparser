from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Oracle Database Multiple Vulnerabilities%','Oracle Database Multiple Remote Vulnerabilities%','UTL_FILE Traversal Arbitrary File Manipulation','Oracle RDBMS Patchset Out of Date (credentialed check)']
	name="Outdated Oracle Database"
	description="Unpatched Oracle Database software deployments have been identified on a number of hosts. Unpatched software continues to remain vulnerable to issues which have been addressed by the vendor, leaving it increasingly vulnerable to attack. As Oracle Database deployments are typically used to hold significant volumes of data, the risk presented by this finding is partially dependant on the sensitivty of the data held."
	risk_description="The versions of the Oracle Database software deployments on a number of hosts were identified from the versions revealed by the TNS listener services and were found to be outdated.\n\nThese deployments should be considered vulnerable to issues within various components throughout the Oracle Database installation, including (but not limited to) the Core RDBMS, Application Express, PL SQL, Spatial, Enterprise Manager and Java VM. Such vulnerabilities vary in their potential impact and therefore overall risk and include information disclosure, SQL injection, buffer overflows, directory traversal and command execution issues. The more severe of these issues could enable the complete compromise of the underlying host; however, the likelihood of a number of these issues being exploited is reduced due to an attacker requiring access to components which require authentication."
	recommendation="Any available security updates (Critical Patch Updates (CPUs)) should be applied to these deployments while they remain in operation. This is expected to include the application of the most recently available CPU for the versions of Oracle Database installed on the hosts.\n\nIf a deployment is in place as part of a third-party solution, an approach should be identified with the vendor with regard to maintaining a suitable patching policy for it and implemented as part of an ongoing patch management strategy."
	notes="<url>http://www.oracle.com/us/support/library/lifetime-support-technology-069183.pdf</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices