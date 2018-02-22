from plugins import genFile

def gen(cb):
	plugin_ids=[35372]
	name="DNS Dynamic Updates"
	description="DNS services were identified which permit their records for specific zones to be dynamically updated. This can be used to facilitate man-in-the-middle attacks."
	risk_description="DNS services were found to permit the dynamic updating of their records. This functionality can be used to create or alter DNS records, enabling an attacker to redirect traffic away from a legitimate host to one under their control. This could be used to intercept sensitive service traffic or direct users to malicious resources/applications, through which an attacker may attempt to compromise user hosts or account credentials.\n\nIt should be noted that this finding can reflect a legitimate configuration if testing of these services was conducted from within a network subnet which is required to perform dynamic updates by the DNS services."
	recommendation="Limit the sources addresses that are allowed to perform dynamic updates against these services (e.g. with BIND's 'allow-update' option) or implement the signing of DNS traffic (e.g. TSIG or SIG(0))."
	notes="<url>https://technet.microsoft.com/en-us/library/cc753751(v=ws.11).aspx</url>"
	notes+="\n<url>https://technet.microsoft.com/en-us/library/cc725703(v=ws.11).aspx</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids CacheSnooping(VulnerabilityPlugin):
	plugin_ids=["DNS Server Cache Snooping Remote Information Disclosure"]
	name="DNS Cache Snooping"
	description=str()
	risk_description="At least one DNS server responds to queries for third-party domains that do not have the recursion bit set. This configuration can may allow a remote attacker to determine which domains have recently been resolved via a name server, and therefore which hosts have been recently visited. This can lead to the identification of user browsing habits (e.g. what sites they visit) and the identification of software in use within the network (e.g. anti-virus software) based on the domain names which are cached by a DNS server.\n\nThis issue presents a reduced risk for internal DNS servers as such attacks would be limited to the internal network. This may include employees, consultants and potentially users on a guest network or WiFi connection if supported.\n\nIt should be noted that this configuration is default within a number of DNS services, including Microsoft Windows DNS."
	recommendation="If recursion is required, this configuration must remain in place to avoid impacting functionality. The only approach in which this issue can fully be addressed requires recursion to be disabled completely."
	notes="<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://technet.microsoft.com/en-us/library/cc771738.aspx</url>"
	notes+="\n<url>https://support.microsoft.com/kb/2678371</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids RequestAmpDos(VulnerabilityPlugin):
	plugin_ids=["DNS Server Spoofed Request Amplification DDoS"] ## wasn't set originally
	name="DNS Server Spoofed Request Amplification DDoS"
	description=str()
	risk_description="A DNS server responds to any request. It is possible to query the name servers (NS) of the root zone ('.') and get an answer that is bigger than the original request. By spoofing the source IP address, a remote attacker can leverage this 'amplification' to launch a denial of service attack against another host using the remote DNS server. For internally hosted DNS servers with no Internet access, this issue is limited to hosts within the internal network. Externally presented DNS services can present a threat to other third-party hosted services."
	recommendation="Reconfigure the service to reject such queries. This may require removing entries for root zones from the service."
	notes="<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://technet.microsoft.com/en-us/security/hh972393.aspx</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
