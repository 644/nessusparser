from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=[90509]
	name="Samba Badlock Vulnerability"
	description="Samba services are running versions which are vulnerable to man-in-the-middle and denial-of-service issues, commonly referenced as the \"Badlock\" vulnerability."
	risk_description="The version of Samba, a CIFS/SMB server for Linux and Unix, running on hosts is affected by a flaw, known as Badlock. This issue exists in the Security Account Manager (SAM) and Local Security Authority (Domain Policy) (LSAD) protocols due to improper authentication level negotiation over Remote Procedure Call (RPC) channels. A man-in-the-middle attacker who is able to able to intercept the traffic between a client and a server hosting a SAM database can exploit this flaw to force a downgrade of the authentication level, which allows the execution of arbitrary Samba network calls in the context of the intercepted user, such as viewing or modifying sensitive security data in the Active Directory (AD) database or disabling critical services."
	recommendation="This issue has been addressed in more recent releases of the Samba software. Ensure that affected installations are updated in line with the most recent, supported release. Installations provided as part of other third-party software deployments will require a vendor-provided update to address this issue."
	notes="<url>http://badlock.org</url>"
	notes+="\n<url>https://www.samba.org/samba/security/CVE-2016-2118.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices