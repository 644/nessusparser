from plugins import genFile

def gen(cb):
	plugin_ids=[10203, 10205]
	name="Insecure Inetd Services"
	description="Instances of obsolete Inetd services were seen on hosts within the network. These can be used to gain remote access or execute commands with administrative rights on an affected host. Such services are considered obsolete and have been deprecated and replaced by more secure alternatives due to the lack of security, such as traffic encryption, and vulnerabilities related to them."
	risk_description="This finding relates to two obsolete Inetd services, rlogin and rexec, that were observed on hosts during the course of the review. Whilst it is not possible for the tester to be certain as to the functional requirements of each affected host, the presence of these services is likely to be the result of legacy configuration (either applied to a legacy host or migrated to a newly deployed host) and increases the threat surface of each host.\n\nThe availability of rlogin and rexec services also highlights a collection of more dangerous issues. Each of these services can grant a user remote access to the host, provided they have the correct authentication details. As these services do not secure their traffic, any data transmitted by such services would be sent in cleartext, making it significantly easier to acquire credentials via interception (Man-in-the-Middle).\n\nVulnerabilities have also affected rlogin and rexec in the past, including the ability to bypass the authentication requirements of each service. Whilst no evidence of such issues was seen during this review, the continued availability of such services undermines the security of each affected host."
	recommendation="Disable rlogin and rexec and enforce the use of the SSH service.\nComment out the relevant lines (\"login\" and \"exec\") in the /etc/inetd.conf file on each host before restarting the inetd service to disable these services."
	notes="<url>http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0618</url>"
	notes+="\n<url>http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0651</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
