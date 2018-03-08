import sqlite3
import re
from plugins import genFile

def gen(cb):
	appendices = []

	name = "Microsoft Software Updates"
	description="Microsoft release regular updates for their supported software, including Windows operating systems, Office suites and other components. These Security Bulletins/Knowledge Base (KB) updates address security and functionality issues for specific software which, if left unchecked, would leave an unpatched host vulnerable to exploitation. The severity of the issues addressed varies between updates, with the most severe potentially leading to a full compromise of the host."
	risk_description="############EXPERIMENTAL - Manually compare findings before submitting report##################Microsoft software is widely utilised, resulting in their products being exposed to persistent scrutiny. Updates for Microsoft products are made available on a monthly basis, as well as additional ad-hoc updates being released as required.\n\nThe risk presented by each of the following issues varies based on what it enables an attacker to perform against a host and what requirements are needed in order to leverage this vulnerability. Issues relating to information disclosure are commonly seen to present a lower risk, whilst those which enable an unauthenticated attacker to remotely execute code on an affected host (e.g. due to a buffer overflow vulnerability) are seen to present a substantially elevated level of risk.\n\nThe risk ratings associated with such issues are also typically elevated due to poor configuration, particularly with regard to software which is used to create services. It is commonplace for such services to be granted with local SYSTEM level privileges, which if acquired allows for the complete compromise of a host and provides a base from which further attacks against an associated domain can be launched."
	recommendation="It is strongly recommended that the patches corresponding to the missing security bulletins be applied to the affected hosts and that a revision of the current management strategy also be performed to ensure that it is adhering to outlined policies.\n\nPatching issues with such software commonly arise due to a misconfiguration within patching solutions, such as Windows Server Update Services (WSUS), which may require reviewing to identify the cause of this lack of patching."
	affected_components=str()
	notes=str()
	plugin_ids = ['NONE']

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.reports_pluginFamily == 'Windows : Microsoft Bulletins' OR reportitems.reports_pluginName LIKE 'MS0%' OR reportitems.reports_pluginName LIKE 'MS1%' OR reportitems.reports_pluginName LIKE 'MS1%' OR reportitems.reports_pluginName LIKE 'MS KB%' OR reportitems.reports_pluginName LIKE 'MSKB%' OR reportitems.reports_pluginName LIKE 'KB%' OR reportitems.reports_pluginName LIKE 'MS Security Advisory%' OR reportitems.reports_pluginName == 'Update for Microsoft EAP Implementation that Enables the Use of TLS' AND reportitems.reports_pluginName != 'Microsoft Patch Bulletin Feasibility Check' AND reportitems.reports_pluginName != 'Microsoft Windows Summary of Missing Patches'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.reports_pluginFamily == 'Windows : Microsoft Bulletins' OR reportitems.reports_pluginName LIKE 'MS0%' OR reportitems.reports_pluginName LIKE 'MS1%' OR reportitems.reports_pluginName LIKE 'MS1%' OR reportitems.reports_pluginName LIKE 'MS KB%' OR reportitems.reports_pluginName LIKE 'MSKB%' OR reportitems.reports_pluginName LIKE 'KB%' OR reportitems.reports_pluginName LIKE 'MS Security Advisory%' OR reportitems.reports_pluginName == 'Update for Microsoft EAP Implementation that Enables the Use of TLS' AND reportitems.reports_pluginName != 'Microsoft Patch Bulletin Feasibility Check' AND reportitems.reports_pluginName != 'Microsoft Windows Summary of Missing Patches'")

	all_rows = c.fetchall()
	result_dict = dict()
	keys_check = []
	affected_hosts = []
	appendices = []

	for x in all_rows:
		if x[1]:
			host_identifier = x[1]
		else:
			host_identifier = x[2]
		
		if x[3] == "Update for Microsoft EAP Implementation that Enables the Use of TLS":
			advisory = "2977292"
			plugin_name = "Update for Microsoft EAP Implementation that Enables the Use of TLS (2977292)"
		elif x[3] == "Security Update for Microsoft Office Products (April 2017)":
			advisory = "4016803"
			plugin_name = "Security Update for Microsoft Office Products (April 2017) (4016803)"
		elif x[3] == "Security and Quality Rollup for .NET Framework (April 2017)":
			advisory = "4014981"
			plugin_name = "Update for Microsoft EAP Implementation that Enables the Use of TLS (4014981)"
		else:
			try:
				m = re.search('[0-9]{7}', x[3])
				advisory = m.group(0)
				plugin_name = x[3]
			except AttributeError as ae:
				plugin_name = x[3]
				advisory = 0
		
		plugin_key = plugin_name,advisory
		result_dict[plugin_key] = host_identifier

		for key,key2 in result_dict.keys():
			if not key in keys_check:
				affected_hosts.append("<bold_italic>{0}</bold_italic>\n".format(key))
				keys_check.append(key)

			if not key2 in keys_check and key2 != 0:
				notes += "<url>https://support.microsoft.com/help/{0}</url>\n".format(key2)
				keys_check.append(key2)

			if not result_dict[key,key2] in keys_check:
				affected_hosts.append(result_dict[key,key2] + "\n")
				keys_check.append(result_dict[key,key2])

	conn.close()
	ap = genFile.gen_document(cb, name, description, risk_description, recommendation, notes, affected_hosts)

	if not ap is None:
		appendices += ap

	if appendices:
		return appendices

