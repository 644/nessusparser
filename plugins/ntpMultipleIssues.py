from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=[97861]
	name="NTP Mode 6 Query Support"
	description=str()
	risk_description="NTP services were identified which respond to mode 6 queries. Hosts that respond to these queries have the potential to be used in NTP amplification attacks. An unauthenticated, remote attacker could potentially exploit this, via a specially crafted mode 6 query, to cause a reflected denial-of-service condition."
	recommendation="Restrict NTP mode 6 queries within the service configuration."
	recommendation+="\n\nUse of the \"restrict\" directive with the \"noquery\" option is recommended; however, this can impact other clients accessing the service. These restrictions should be implemented to fit organisational requirements."
	recommendation+="\n\nHost-based firewalls can also be used to reduce the services availability to unnecessary clients."
	notes="<url>http://support.ntp.org/bin/view/Support/AccessRestrictions</url>"
	
	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap
	

	# New plugin_ids NTPMode7DoS(VulnerabilityPlugin):
	plugin_ids=[43156]
	name="NTP Mode 7 DoS"
	description="NTP services are affected by a denial-of-service issue. This can result in the underlying host crashing."
	risk_description="The NTP daemon listening on hosts responds to NTP mode 7 packets with their own mode 7 packets. An attacker could exploit this using a crafted mode 7 packet with a spoofed IP header, using the target host's IP address as both the source and destination entry. This would result in the NTP service endlessly responding to itself, consuming system resources."
	recommendation="Upgrade to NTP 4.2.4p8 / 4.2.6 or later. For other NTP software, consult the vendor documentation or contact the vendor.\n\nOtherwise, limit access to the affected service to trusted hosts only."
	notes="<url>http://bugs.ntp.org/show_bug.cgi?id=1331</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids NTPMonlist(VulnerabilityPlugin):
	plugin_ids=[71783]
	name="NTP monlist Command Enabled"
	description="NTP services support requests using the \"monlist\" command. This can be used to identify a list of hosts that have recently used the service."
	risk_description="The NTP daemon listening on the affected hosts has the \"monlist\" command enabled. This command returns a list of recent hosts that have connected to the service. As such, it can be used for network reconnaissance or, along with a spoofed source IP, a distributed denial-of-service attack."
	recommendation="If using NTP from the Network Time Protocol Project, either upgrade to NTP 4.2.7-p26 or later, or add 'disable monitor' to the 'ntp.conf' configuration file and restart the service. For other NTP software, consult the vendor documentation or contact the vendor.\n\nOtherwise, limit access to the affected service to trusted hosts only."
	notes="<url>https://isc.sans.edu/diary/NTP+reflection+attack/17300</url>"
	notes+="\n<url>http://bugs.ntp.org/show_bug.cgi?id=1532</url>"
	notes+="\n<url>http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10613</url>"
	
	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap
	

	# New plugin_ids NTPVersion(VulnerabilityPlugin):
	plugin_ids=["Network Time Protocol Daemon (ntpd) %<%"]
	name="NTP Daemon Version"
	description="NTP services are using older versions of the ntpd software. These are associated with known issues."
	risk_description="The NTP daemons listening on the affected hosts reveal their software version in returned banners. Each identified host appears to be running an ntpd version which is associated with known vulnerabilities. The exact impact of this observation depends specifically on the version of ntpd present on an affected host. Issues reported to affect older ntpd versions have included various buffer overflow attacks which can be remotely leveraged to cause a denial of service or potentially invoke code execution by an unauthenticated remote attacker. Other attack vectors, local and remote, authenticated and unauthenticated, have also affected older ntpd versions and could lead to information disclosure or affect the NTP services ability to present accurate time entries."
	risk_description+="\n\nEach identified issue could lead to a compromise of the underlying host or affect other hosts/services which are time-sensitive, leading to denial of service."
	recommendation="Upgrade to the most recent, supported ntpd release. Where ntpd is included with a third-party software deployment, contact the vendor to identify a suitable upgrade path."
	notes="<url>http://support.ntp.org/bin/view/Main/SecurityNotice</url>"
	
	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices