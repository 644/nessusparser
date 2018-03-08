from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Anonymous FTP Enabled','FTP Writable Directories']
	name="Anonymous FTP Service"
	description="Anonymous logins have been found to be allowed on the remote FTP servers."
	risk_description="Any network user may connect and authenticate to the remote FTP service without providing a password or unique credentials. This allows a user to access any files made available on the FTP server or to use the service for the storage and distribution of unauthorised files."
	recommendation="Disable anonymous FTP if it is not required. Routinely check the FTP server to ensure sensitive content is not available."
	notes="<url>https://technet.microsoft.com/en-us/library/dd463993(v=ws.10).aspx</url>"
	notes+="\n<url>http://www.proftpd.org/docs/faq/linked/faq-ch5.html#AEN597</url>"
	notes+="\n<url>https://www.centos.org/docs/5/html/Deployment_Guide-en-US/s1-ftp-vsftpd-conf.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices