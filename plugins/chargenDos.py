from plugins import genFile

def gen(cb):
	plugin_ids=[10043]
	name="Chargen Service - DoS"
	description="Chargen is a historic service used for debugging TCP/UDP connections. No longer commonly used, the chargen service can be manipulated into performing a denial-of-service attack against assets."
	risk_description="The chargen service was found on hosts during the assessment. This service responds to connections with random characters (e.g. all the characters in the alphabet). When contacted via UDP, it will respond with a single UDP packet. When contacted via TCP, the service will continue sending packets containing such characters until the client closes the connection.\n\nThis service was used to mostly test the TCP/IP protocol by itself, to ensure that all packets were arriving at their destination unaltered. An attacker could craft packets to be sent to this service, manipulating the source of the request. The service would then attempt to send traffic back to the manipulated source, consuming network resources and those of the underying hosts."
	recommendation="If in use, filter access to this service to only necessary sources.\n\nDisable this service where not required. On Unix/Linux systems this is commonly done by commenting out the chargen line in /etc/inetd.conf and restarting the inetd service.\n\nFor Windows hosts, disable the \"Simple TCP Services\" service or set the following registry entries under <italic>HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\</italic> to 0 and restart the \"simptcp\" service:\n\n<italic>EnableTcpChargen</italic>\n<italic>EnableUdpChargen</italic>"
	notes="<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0103</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
