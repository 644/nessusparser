import sqlite3
import re
from plugins import genFile

def gen(cb):
	appendices = []
	
	name="IPMI Version 2 Services"
	description="The Intelligent Platform Management Interface (IPMI) protocol is used to remotely manage and monitor hosts in an out-of-band (i.e. not requiring access to the host's resources) manner. A number of IPMI services have been identified which supports version 2.0 of the protocol, which is afflicted with significant flaws which allow details relating to administrative users to be recovered."
	risk_description="Several hosts/services support IPMI v2.0."
	recommendation="There is no patch for the issues affecting IPMI services; it is an inherent problem with the specification for IPMI v2.0.\n\nSuggested mitigations include:\nDisabling IPMI over LAN if it is not needed.\nUsing strong passwords to limit the successfulness of off-line dictionary attacks.\nUsing Access Control Lists (ACLs) or isolated networks to limit access to any IPMI management interfaces."
	notes="<url>https://nvd.nist.gov/vuln/detail/CVE-2013-4786</url>\n"
	notes+="<url>https://blog.rapid7.com/2013/07/02/a-penetration-testers-guide-to-ipmi/</url>"
	plugin_ids = ['NONE']

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'IPMI v2.0 Password Hash Disclosure'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'IPMI v2.0 Password Hash Disclosure'")
	ipmi_list = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'IPMI Cipher Suite Zero Authentication Bypass'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'IPMI Cipher Suite Zero Authentication Bypass'")
	cipher_zero = c.fetchall()
	c.close()
	
	ipmi_hosts = []
	cipher_hosts = []
	
	for x in ipmi_list:
		if x[1]:
			ipmi_hosts.append(x[1])
		else:
			ipmi_hosts.append(x[2])
	
	for x in cipher_zero:
		if x[1]:
			cipher_hosts.append(x[1])
		else:
			cipher_hosts.append(x[2])

	affected_hosts = ipmi_hosts + cipher_hosts

	ipmi=False
	if len(ipmi_hosts) > 0:
		ipmi=True		
		risk_description+=" The Intelligent Platform Management Interface (IPMI) protocol is affected by an information disclosure vulnerability due to the support of RMCP+ Authenticated Key-Exchange Protocol (RAKP) authentication. A remote attacker can obtain password hash information for valid user accounts via the HMAC from a RAKP message 2 response from a Baseboard Management Controller. Cracking these password hashes can allow authentication to a service as a legitimate user and leave hosts vulnerable to attack."
	
	if len(cipher_hosts) > 0:
		if ipmi:
			risk_description+="\n\nFurthermore, some services also support authentication via cipher suite zero, permitting logons to the service as an administrative user without requiring a valid password. An authenticated attacker may perform a variety of actions, including powering off the remote system."
		else:
			risk_description+=" The Intelligent Platform Management Interface (IPMI) services support authentication via cipher suite zero, permitting logons to the service as an administrtive user without requiring a valid password. An authenticated attacker may perform a variety of actions, including powering off the remote system."
	
	ap = genFile.gen_document(cb, name, description, risk_description, recommendation, notes, affected_hosts)

	if not ap is None:
		appendices += ap

	if appendices:
		return appendices
