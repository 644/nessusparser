import sqlite3
import re
from plugins import genFile

def gen(cb):
	appendices = []

	name="SNMP Default Community Strings"
	description="A number of hosts have been found to be using default community string values for SNMP services. Community strings are used as an authentication mechanism for accessing the service and its data, leading this issue to allow an attacker to retrieve information from each affected device and, if configured to allow such actions, make changes to this data. Changes to such data could be used to facilitate further attacks on other network assets."
	risk_description="The Simple Network Management Protocol (SNMP) provides the ability to monitor and manage network-connected devices remotely. Access to the functionality provided by such services is controlled by authentication mechanisms. In older revisions of SNMP protocols (version 1 and 2c) this relies on the use of community strings in order to determine what level of access (Read-Only, Read/Write) is permitted on the Management Information Base (MIB), the database of configuration variables that resides on the underlying device.\n\nSNMP versions 1 and 2c typically make use of two passwords/community strings: the \"read\" and \"write\" strings. A read community string permits the user to view the configuration of the device or system, whilst the write community string can be used to change or edit the configuration on the device."
	recommendation="Disable the SNMP service on each affected host if it is not in use. Alternatively, ensure that each community string is changed to a non-default value that reflects a strong password policy. For administrative services, this value should be 14 characters in length and should also utilise all available complexity factors (upper- and lower-case letters, numbers and symbols)."
	notes="<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0517</url>"

	plugin_ids = ['NONE']

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SNMP Agent Default Community Name (public)'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SNMP Agent Default Community Name (public)'")
	read_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SNMP Agent Default Community Names'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'SNMP Agent Default Community Names'")
	write_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'Microsoft Windows LAN Manager SNMP LanMan Services Disclosure'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'Microsoft Windows LAN Manager SNMP LanMan Services Disclosure'")
	windows_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute('''select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == "SNMP 'GETBULK' Reflection DDoS"''')
	except sqlite3.OperationalError:
		c.execute('''select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == "SNMP 'GETBULK' Reflection DDoS"''')
	bulk_dos_results = c.fetchall()
	c.close()

	read_hosts = []
	write_hosts = []
	windows_hosts = []
	bulk_dos_hosts = []

	for x in read_results:
		if x[1]:
			read_hosts.append(x[1])
		else:
			read_hosts.append(x[2])

	for x in write_results:
		if x[1]:
			write_hosts.append(x[1])
		else:
			write_hosts.append(x[2])

	for x in windows_results:
		if x[1]:
			windows_hosts.append(x[1])
		else:
			windows_hosts.append(x[2])

	for x in bulk_dos_results:
		if x[1]:
			bulk_dos_hosts.append(x[1])
		else:
			bulk_dos_hosts.append(x[2])

	affected_hosts = read_hosts + write_hosts + windows_hosts + bulk_dos_hosts

	read=False
	write=False
	windows=False
	bulk=False

	if len(read_results) > 0:
		read=True		
		risk_description+="\n\nHosts have been found to be presenting SNMP services which utilise known default community strings for the \"read\" value, which is commonly seen as to be set as \"public\" (or a known manufacturer-specific default community string value). This setting permits data to be recovered from the MIB on each host/service, which could provide an attacker with useful information about the underlying host depending on the data held in the MIB."		
	
	if len(write_results) > 0:
		write=True
		if read:
			risk_description+="\n\nFurthermore, services are also configured to use known/default values for \"read/write\" community strings. This presents an elevated risk to each affected host as it enables an attacker to alter values within the MIB. Depending on how the MIB values are processed by the host/other services, changes to them could lead to denial of service or a remote compromise of a host."
		else:
			risk_description+="\n\nHosts have been found to be presenting SNMP services which utilise known default community strings for the \"read/write\" value, which is commonly seen as to be set as \"private\" (or a known manufacturer-specific default community string value). This setting permits data to be recovered or altered within the MIB on each host/service, which could provide an attacker with useful information about the underlying host, allow for denial of service conditions to be invoked or enable a remote compromise of the underlying host, depending on the data managed within the MIB."

	if len(windows_results) > 0:
		windows=True
		if read or write:
			risk_description+="\n\nA number of hosts were also seen to return information pertaining to Microsoft Windows services within the MIB data recovered from their SNMP services. The data made available through SNMP services on Windows hosts can offer an insight into the configuration of the underlying host, including the enumeration of local users, running services, installed software and updates. If write access is available, this can present a significant risk."
		else:
			risk_description+="\n\nA number of hosts were seen to return information pertaining to Microsoft Windows services within the MIB data recovered from their SNMP services. The data made available through SNMP services on Windows hosts can offer an insight into the configuration of the underlying host, including the enumeration of local users, running services, installed software and updates. If write access is available, this can present a significant risk."

	if len(bulk_dos_results) > 0:
		bulk=True
		if read or write or windows:
			risk_description+="\n\nAdditionally, SNMP services were seen to support the use of the SNMP 'GETBULK' functionality with increased values for the 'max-repetitions' setting. This can result in small SNMP requests being used to generate significantly larger responses from the SNMP service. By crafting SNMP GETBULK packets and manipulating source address entries, an attacker could use such services as part of a distributed denial-of-service attack."
		else:
			risk_description+="\n\nSNMP services on hosts were seen to support the use of the SNMP 'GETBULK' functionality with increased values for the 'max-repetitions' setting. This can result in small SNMP requests being used to generate significantly larger responses from the SNMP service. By crafting SNMP GETBULK packets and manipulating source address entries, an attacker could use such services as part of a distributed denial-of-service attack."

	ap = genFile.gen_document(cb, name, description, risk_description, recommendation, notes, affected_hosts)

	if not ap is None:
		appendices += ap

	if appendices:
		return appendices
