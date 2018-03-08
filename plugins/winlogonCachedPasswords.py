from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Microsoft Windows SMB Registry : Winlogon Cached Password Weakness']
	name="Windows Domain Password Caching"
	description="The configuration of several hosts running Microsoft Windows operating systems are such that they allow user credentials to be stored in memory. This functionality can allow user credentials to be recovered from a host if it is compromised."
	risk_description="The registry key HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount is not set to a null value on each of the affected hosts. This results in each host locally caching the passwords of users when they log in, which is meant to provide a solution to login failures if there is an issue with the existing domain controller hosts.\n\nIf these hosts are compromised, an attacker would be able to recover legitimate user credentials that may have domain privileges. This could facilitate the compromise of other domain-connected hosts."
	recommendation="Reconfigure the domain group policy or local security policy applied to each host so that the following control is set to 0, and update the policies on the affected hosts:\n\nSecurity Options - Interactive logon: Number of previous logons to cache (in case domain controller is not available)\n\nAlternatively, using the registry editor (regedt32) on each host, set the value of the following key to 0:\n\nHKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount"
	notes="<url>https://technet.microsoft.com/en-us/library/cc755473(v=ws.10).aspx</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices