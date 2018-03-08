from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=[34324]
	name="FTP Cleartext Authentication"
	description="Services using FTP to transfer files do so with support for authentication mechanisms which offer no security for user credentials during transmission, leaving them susceptible to interception."
	risk_description="FTP services found during the assessment offer support for authentication mechanisms which do not encrypt user credentials as they are being transmitted. Data sent via such means is at risk of interception through man-in-the-middle attacks performed by a suitably positioned network attacker. The overall impact of such activity would depend on the privileges afforded to any user credentials recovered in this manner. It should be noted that services do offer support for authenticating via secure channels (e.g. TLS); however, support for cleartext mechanisms leaves the services and their traffic susceptible to interception."
	recommendation="Disable cleartext authentication mechanisms (e.g. LOGIN) and enforce the use of AUTH TLS or FTPS. Alternatively, disable the service and replace it with an SFTP deployment."
	notes="<url>https://www.iis.net/configreference/system.applicationhost/sites/site/ftpserver/security/ssl</url>"
	notes+="\n<url>https://wiki.filezilla-project.org/FTP_over_TLS</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices