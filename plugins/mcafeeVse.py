from plugins import genFile

def gen(cb):
	appendices = []

	include_strings=["McAfee VirusScan Enterprise","Engine version","DAT version","Updated date"]
	plugin_ids=['McAfee VirusScan Enterprise %','McAfee Antivirus Detection and Status']
	name="McAfee VirusScan Enterprise"
	description="The antivirus application installed on a number of Windows hosts is affected by a number of vulnerabilities, including those which permit the bypassing of McAfee security measures and elevate their privileges on the underlying host. Some installations are also no longer supported or are running unsuitable configurations."
	risk_description="Various versions of the McAfee VirusScan Enterprise (VSE) software installed on hosts predate the most recent release. Flaws known to affect older versions of McAfee VSE include issues in the self-protection mechanism when applying rules to access settings, which are used to determine what applications and associated actions can be trusted. An attacker with Windows administrative privileges can exploit this flaw to control the trust settings and bypass access restrictions, allowing protected McAfee applications, including VSE, to be disabled or uninstalled. This does not require the management password to exploit.\n\nOther issues include a CLI local privilege escalation vulnerability that could disable VSE and its connection to McAfee ePolicy Orchestrator (ePO), providing an attacker with a host on which malicious activity/content would not be detected.\n\nHosts were also found to have issues within the configuration of their VSE installations. Unsupported VSE versions and a lack of regular updates for the antivirus databases (DAT files) are seen to prevent hosts from being able to detect more recently identified malicious content/activity and thus leaving them more susceptible to compromise."
	recommendation="Ensure each McAfee VSE deployment is kept in line with the most recent supported software release.\n\nReview the lack of updates to the identified hosts definition data and ensure they are configured to retrieve regular DAT file updates."
	notes="<url>https://kc.mcafee.com/corporate/index?page=content&id=SB10151</url>"
	notes+="\n<url>https://kc.mcafee.com/corporate/index?page=content&id=KB84590</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices