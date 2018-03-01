import sqlite3

def gen(cb):
	name = "Microsoft Software Updates"
	description="Microsoft release regular updates for their supported software, including Windows operating systems, Office suites and other components. These Security Bulletins/Knowledge Base (KB) updates address security and functionality issues for specific software which, if left unchecked, would leave an unpatched host vulnerable to exploitation. The severity of the issues addressed varies between updates, with the most severe potentially leading to a full compromise of the host."
	risk_description="############EXPERIMENTAL - Manually compare findings before submitting report##################Microsoft software is widely utilised, resulting in their products being exposed to persistent scrutiny. Updates for Microsoft products are made available on a monthly basis, as well as additional ad-hoc updates being released as required.\n\nThe risk presented by each of the following issues varies based on what it enables an attacker to perform against a host and what requirements are needed in order to leverage this vulnerability. Issues relating to information disclosure are commonly seen to present a lower risk, whilst those which enable an unauthenticated attacker to remotely execute code on an affected host (e.g. due to a buffer overflow vulnerability) are seen to present a substantially elevated level of risk.\n\nThe risk ratings associated with such issues are also typically elevated due to poor configuration, particularly with regard to software which is used to create services. It is commonplace for such services to be granted with local SYSTEM level privileges, which if acquired allows for the complete compromise of a host and provides a base from which further attacks against an associated domain can be launched."
	recommendation="It is strongly recommended that the patches corresponding to the missing security bulletins be applied to the affected hosts and that a revision of the current management strategy also be performed to ensure that it is adhering to outlined policies.\n\nPatching issues with such software commonly arise due to a misconfiguration within patching solutions, such as Windows Server Update Services (WSUS), which may require reviewing to identify the cause of this lack of patching."
	affected_components=str()
	notes=str()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()

	c.execute("select reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.reports_pluginFamily == 'Windows : Microsoft Bulletins' OR reportitems.reports_pluginName LIKE 'MS0%' OR reportitems.reports_pluginName LIKE 'MS1%' OR reportitems.reports_pluginName LIKE 'MS1%' OR reportitems.reports_pluginName LIKE 'MS KB%' OR reportitems.reports_pluginName LIKE 'MSKB%' OR reportitems.reports_pluginName LIKE 'KB%' OR reportitems.reports_pluginName LIKE 'MS Security Advisory%' OR reportitems.reports_pluginName == 'Update for Microsoft EAP Implementation that Enables the Use of TLS' AND reportitems.reports_pluginName != 'Microsoft Patch Bulletin Feasibility Check' AND reportitems.reports_pluginName != 'Microsoft Windows Summary of Missing Patches'")
	
	all_rows = c.fetchall()
	print(all_rows)

	conn.close()
