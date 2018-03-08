from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Insecure Windows Service Permissions']
	include_strings=["Path : ", "Used by services : "]
	name="Insecure Windows Service Permissions"
	description="Improperly configured Windows services are enabled on multiple hosts. This configuration could allow a local user to escalate their privileges, enabling the compromise of the host and facilitating attacks against other assets."
	risk_description="The affected hosts present at least one Microsoft Windows service whose related executable file is configured with insecure permissions. Services configured to use an executable with weak permissions are vulnerable to privilege escalation attacks, as an unprivileged user may modify or overwrite the executable with arbitrary code, which would be executed the next time the service is started. Depending on the user that the service runs as, this could result in privilege escalation to SYSTEM level, enabling the complete compromise of the underlying host.\n\nA list of affected hosts and their services configured in this manner can be found in the Notes section of this finding."
	recommendation="Reconfigure the executable related to each service so that it does not allow Full Control or Write permissions to members of the Everyone, Users or other non-administrative user groups. Additionally, ensure that these groups do not have Full Control permission to any directories that contain the service executable."
	notes="<url>http://travisaltman.com/windows-privilege-escalation-via-weak-service-permissions/</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices