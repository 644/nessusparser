import sqlite3
import re
from plugins import genFile

def gen(cb):
	appendices = []

	name="Microsoft Remote Desktop Issues"
	description="The remote instances of Microsoft Remote Desktop Protocol (Terminal Services) are vulnerable to several issues which affect the strength of the encryption provided by the service. This reduces the amount of effort required by an attacker to intercept remote management sessions and may allow for the disclosure of system credentials."
	risk_description=str()
	recommendation="It is recommended that the remote hosts be reconfigured to use the FIPS Compliant encryption level with Secure Sockets Layer as the security layer. Network Level Authentication (NLA) should also be enabled. This can be achieved using the Remote Desktop Session Host Configuration tool. \n\nA valid Secure Sockets Layer (SSL) certificate should also be issued to each host to allow for positive identification of remote hosts. This can be achieved using an internal Public Key Infrastructure (PKI), such as Active Directory Certification Services."
	notes="<url>https://technet.microsoft.com/en-gb/library/cc732713.aspx</url>"
	notes+="\n<url>https://technet.microsoft.com/en-gb/library/cc770833.aspx</url>"

	plugin_ids = ['NONE']

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness'")
	mitm_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'Terminal Services Encryption Level is Medium or Low'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'Terminal Services Encryption Level is Medium or Low'")
	encryption_results = c.fetchall()
	c.close()
	
	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'Terminal Services Encryption Level is Medium or Low'")
	except sqlite3.OperationalError:
		c.execute('''select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == "Terminal Services Doesn't Use Network Level Authentication (NLA) Only"''')
	nla_results = c.fetchall()
	c.close()
	
	mitm_hosts = []
	encryption_hosts = []
	nla_hosts = []
	
	for x in mitm_results:
		if x[1]:
			mitm_hosts.append(x[1])
		else:
			mitm_hosts.append(x[2])
	
	for x in encryption_results:
		if x[1]:
			encryption_hosts.append(x[1])
		else:
			encryption_hosts.append(x[2])
	
	for x in nla_results:
		if x[1]:
			nla_hosts.append(x[1])
		else:
			nla_hosts.append(x[2])

	affected_hosts = mitm_hosts + encryption_hosts + nla_hosts

	mitm=False
	weak_ciphers=False

	if len(mitm_results) > 0:
		mitm=True
		risk_description+="The remote versions of the Remote Desktop Protocol Server (Terminal Service) have been detected as being vulnerable to a man-in-the-middle (MiTM) attack. Due to the presence of a publicly disclosed hardcoded RSA private key within the mstlsapi.dll library, an attacker with the ability to intercept traffic from the RDP server can establish encryption with the client and server without being detected.\n\n"		

	if len(encryption_results) > 0:
		weak_ciphers=True
		if mitm:
			risk_description+="Furthermore, the service is configured to accept connections using medium strength (40-bit RC4) encryption. This increases the probability of an attacker intercepting RDP packets being able to retrieve the key used for encryption, thereby gaining access to any credentials sent to the remote host.\n\n"
		else:
			risk_description+="The service is configured to accept connections using medium strength (40-bit RC4) encryption. This increases the probability of an attacker intercepting RDP packets being able to retrieve the key used for encryption, thereby gaining access to any credentials sent to the remote host.\n\n"		

	if len(nla_results) > 0:
		if mitm or weak_ciphers:
			risk_description+="In addition, the remote Terminal Services is not configured to use Network Level Authentication (NLA). NLA uses the Credential Security Support Provider (CredSSP) protocol to perform strong server authentication either through TLS/SSL or Kerberos mechanisms, which protect against man-in-the-middle attacks. In addition to improving authentication, NLA also helps protect the remote computer from malicious users and software by completing user authentication before a full RDP connection is established."		
		else:
			risk_description+="The remote Terminal Services is not configured to use Network Level Authentication (NLA). NLA uses the Credential Security Support Provider (CredSSP) protocol to perform strong server authentication either through TLS/SSL or Kerberos mechanisms, which protect against man-in-the-middle attacks. In addition to improving authentication, NLA also helps protect the remote computer from malicious users and software by completing user authentication before a full RDP connection is established."

	ap = genFile.gen_document(cb, name, description, risk_description, recommendation, notes, affected_hosts)

	if not ap is None:
		appendices += ap

	if appendices:
		return appendices

