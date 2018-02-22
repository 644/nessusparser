from plugins import genFile

def gen(cb):
	plugin_ids=['Microsoft Windows LM / NTLMv1 Authentication Enabled']
	name="Microsoft Windows LM / NTLMv1 Authentication Enabled"
	description="Hosts are configured to use an insecure authentication protocol when authenticating to other Windows hosts. This could allow an attacker to capture a user's Windows credentials (domain or local) and masquerade as that user, either by cracking the password or exploiting the Windows hash-passing functionality."
	risk_description="Several hosts are configured to attempt to use the poorly encrypted LM and NTLMv1 mechanisms for outbound authentication. Due to their cryptographic weaknesses, a remote attacker who is able to intercept LM or NTLMv1 challenge and response packets could acquire a user's LM or NTLM hash. This could be exposed to password cracking techniques, using a tool such as Ophcrack, or used as-is due to the behaviour of the Windows password hash-based authentication, leading to an attacker authenticating to a host as a legitimate user."
	recommendation="Update the applied local security policy or domain group policy so that the Security Options - Network security: LAN Manager authentication level setting is set to a value of \"Send NTLMv2 response only\\refuse LM & NTLM\". It is highly recommended that this setting be used; however, it is advised that suitable testing be performed before deploying such a change, particularly as legacy hosts (e.g. those running Windows 2000) remain connected to the domain.\n\nIf such legacy Windows hosts are to remain connected to the domain, further configuration of the registry on such hosts may be required by adding the \"LMCompatibility\" DWORD value to the HKLM/SYSTEM/CurrentSet/Control/Lsa registry key."
	notes="<url>https://technet.microsoft.com/en-us/library/cc738867(v=ws.10).aspx</url>\n"
	notes+="<url>http://support.microsoft.com/kb/2793313</url>\n"
	notes+="<url>http://technet.microsoft.com/library/cc960646.aspx</url>\n"
	notes+="<url>http://support.microsoft.com/en-us/kb/239869</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
