from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=[10205]
	name="rlogin Services"
	description="Instances of obsolete Inetd services were seen on hosts within the network. These can be used to gain remote access or execute commands with administrative rights on an affected host. Such services are considered obsolete and have been deprecated and replaced by more secure alternatives due to the lack of security, such as traffic encryption, and vulnerabilities related to them."
	risk_description="This finding relates to two Inetd obsolete services, rlogin and rexec, instances of which were observed on hosts during the course of the review. Whilst it is not possible for the tester to be certain as to the functional requirements of each affected host, the presence these services is likely surplus to requirements and increases the threat surface of the host.\n\nThe availability of rlogin and rexec services also highlights a collection of more dangerous issues. Each of these services can grant a user remote access to the host, providing they have the correct authentication details. These services do not secure their traffic, transmitting all data in cleartext, making it significantly easier to acquire credentials via interception (Man-in-the-Middle).\n\nVulnerabilities have also affected rlogin and rexec in the past, including the ability to bypass the authentication requirements of each service. Whilst no evidence of such issues was seen during this review, the continued availability of such services undermines the security of each affected host."
	recommendation="Disable rlogin and rexec and enforce the use of the SSH service.\nComment out the relevant lines (\"login\" and \"exec\") in the /etc/inetd.conf file on each host before restarting the inetd service to disable these services."
	notes="<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0651</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices