import sqlite3
import re
from plugins import genFile

def gen(cb):
	appendices = []

	name="SSH Weak Configuration"
	description="SSH services have been found to support SSH connections using configurations with known weaknesses. These issues could allow the compromise/modification of SSH service traffic."
	risk_description="Issues have been identified with the configuration of SSH services which could leave them offering support for connections using mechanisms with known weaknesses. The likelihood of such issues being leveraged is seen to be low as it requires an attacker to be suitably positioned and for connections to be established using such weak configurations, limiting the overall risk they present."
	recommendation=str()
	notes=str()

	plugin_ids = ['NONE']

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Weak MAC Algorithms Enabled'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Weak MAC Algorithms Enabled'")
	mac_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Server CBC Mode Ciphers Enabled'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Server CBC Mode Ciphers Enabled'")
	cbc_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Weak Algorithms Supported'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Weak Algorithms Supported'")
	arc4_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Diffie-Hellman Modulus <= 1024 Bits (Logjam)'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SSH Diffie-Hellman Modulus <= 1024 Bits (Logjam)'")
	logjam_results = c.fetchall()
	c.close()

	mac_hosts = []
	cbc_hosts = []
	arc4_hosts = []
	logjam_hosts = []

	for x in mac_results:
		if x[1]:
			mac_hosts.append(x[1])
		else:
			mac_hosts.append(x[2])

	for x in cbc_results:
		if x[1]:
			cbc_hosts.append(x[1])
		else:
			cbc_hosts.append(x[2])

	for x in arc4_results:
		if x[1]:
			arc4_hosts.append(x[1])
		else:
			arc4_hosts.append(x[2])

	for x in logjam_results:
		if x[1]:
			logjam_hosts.append(x[1])
		else:
			logjam_hosts.append(x[2])

	affected_hosts = mac_hosts + cbc_hosts + arc4_hosts + logjam_hosts

	mac=False
	cbc=False
	arc4=False
	logjam=False

	if len(mac_results) > 0:
		mac=True		
		risk_description+=" Each affected service offers support for MAC algorithms offering less than 96-bit security or using the MD5 format. Issues relating to the potential for collisions within MD5 as well as the weak security offered by smaller (i.e. 96-bit) MACs could leave service traffic at risk of decryption."
		recommendation+="It is recommended that each affected host is reconfigured to prevent the use of the MD5 or 96-bit algorithms for MAC. This may require support from the product vendor, depending on the configuration options available."

	if len(cbc_results) > 0:
		cbc=True
		if mac:
			risk_description+="\n\nFurthermore, the service is configured to accept connections using Cipher Block Chaining ciphers, which are also affected by known issues which could lead to plaintext values being derived from ciphertext."
#			self.recommendation+="\n\nDisable CBC mode cipher encryption by disabling all CBC ciphers, and enable CTR or GCM cipher mode encryption."
		else:
			risk_description+="The service is configured to accept connections using Cipher Block Chaining ciphers, which are also affected by known issues which could lead to plaintext values being derived from ciphertext."
		recommendation+="\n\nDisable CBC mode cipher encryption by disabling all CBC ciphers, and enable CTR or GCM cipher mode encryption."
		notes+="<url>http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5161</url>"		

	if len(arc4_results) > 0:
		arc4=True
		if mac or cbc:
			risk_description+="\n\nIn addition, services were identified which support connections made using the Arcfour stream cipher or no cipher at all. RFC 4253 advises against the use of Arcfour ciphers due to issues associated with weak keys. Connections made using such ciphers would be increasingly susceptible to interception and decryption."		
		else:
			risk_description+="Services were identified which support connections made using the Arcfour stream cipher or no cipher at all. RFC 4253 advises against the use of Arcfour ciphers due to issues associated with weak keys. Connections made using such ciphers would be increasingly susceptible to interception and decryption."
		recommendation+="\n\nDisable Arcfour ciphers by removing 'arcfour' entries from the supported ciphers list."

	if len(logjam_results) > 0:
		logjam=True
		if mac or cbc or arc4:
			risk_description+="\n\nServices have also been identified which allow connections to be secured using Diffie-Hellman moduli less than or equal to 1024 bits. Cryptanalysis can allow a third party can find the shared secret in a short amount of time (depending on modulus size and attacker resources), allowing an attacker to recover the plaintext or potentially violate the integrity of connections."
		else:
			risk_description+="Services were identified which allow connections to be secured using Diffie-Hellman moduli less than or equal to 1024 bits. Cryptanalysis can allow a third party can find the shared secret in a short amount of time (depending on modulus size and attacker resources), allowing an attacker to recover the plaintext or potentially violate the integrity of connections."
		risk_description+="\n\nNote: Attacks against 1024 bit moduli are currently only considered possible by an attacker with nation-state level resources and can only be carried out against sessions where the vulnerable key exchange algorithms are used."
		recommendation+="\n\nReconfigure the service to use a unique Diffie-Hellman moduli of 2048 bits or greater. This will require a review of key exchange algorithms supported by the service."
		notes+="<url>http://weakdh.org</url>"

	ap = genFile.gen_document(cb, name, description, risk_description, recommendation, notes, affected_hosts)

	if not ap is None:
		appendices += ap

	if appendices:
		return appendices
