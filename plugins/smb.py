from plugins import genFile

def gen(cb):
	# New plugin_ids
	description="Server Message Block (SMB) Issues\nConfiguration issues within the Server Message Block (SMB) service on multiple hosts could enable information disclosure or traffic interception. Successful interception of traffic from the SMB service could enable the retrieval of Windows domain user credentials that could be used to gain privileged access within the internal network."
	
	plugin_ids=['SMB Signing Disabled', 'SMB Signing Required']
	name="SMB Signing Disabled"
	risk_description=str()
	risk_description+="The configuration of SMB services on a number of hosts does not enforce SMB message signing, which can allow attackers to replay SMB authentication handshakes to bypass authentication. In order to successfully exploit this issue, an attacker must capture a valid handshake, which would require a user to be tricked into connecting to a shared service. SMB authentication can tie directly into either a Windows Active Directory domain or local user accounts, enabling the potential compromise of user accounts, the host or domain."
	recommendation="Message signing should be enforced in each host's configuration. This can be found within Local Security Policy of an affected host or applied as part of a domain Group Policy under:\nSecurity Options - Microsoft network client: Digitally sign communications\nSecurity Options - Microsoft network server: Digitally sign communications"
	notes="<bold_italic>"+name+"</bold_italic>\n"
	notes+="<url>https://technet.microsoft.com/en-us/library/jj852186(v=ws.10).aspx</url>\n"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids
	plugin_ids=['Microsoft Windows SMB NULL Session Authentication']
	name="SMB NULL Sessions Permitted"
	risk_description="The affected hosts are running versions of Microsoft Windows. It is possible to log into them using a NULL session (i.e. without any credentials). Depending on the configuration of each host, it may be possible for an unauthenticated, remote attacker to leverage this issue to retrieve useful information."
	recommendation="Suitable changes can be enforced using Local Group Policy and altering the values for Computer Configuration\\Windows Settings\\SecuritySettings\\Local Policies\\SecurityOptions\nDisable the following options within the \"Network access\" security options, either on each host or as part of a domain policy:\nAllow anonymous SID/Name translation\nLet \"Everyone\" permissions apply to anonymous users\n\nEnable the following options within the \"Network access\" security options, either on each host or as part of a domain policy:\n\nDo not allow anonymous enumeration of SAM accounts\nDo not allow anonymous enumeration of SAM accounts and shares\n\nEnable the following options within the \"Network access\" security options, either on each host or as part of a domain policy, and configure them with a NULL/empty value:\n\nNamed Pipes that can be accessed anonymously\nShares that can be accessed anonymously"
	notes="<bold_italic>"+name+"</bold_italic>\n"
	notes+="<url>http://support.microsoft.com/kb/143474/</url>\n"
	notes+="<url>https://technet.microsoft.com/en-us/library/jj852268(v=ws.10).aspx</url>\n"
	notes+="<url>https://technet.microsoft.com/en-us/library/jj852166(v=ws.10).aspx</url>\n"
	notes+="<url>https://technet.microsoft.com/en-us/library/jj852230(v=ws.10).aspx</url>\n"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
