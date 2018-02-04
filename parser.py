import xml.etree.ElementTree as ET
import sqlite3
conn = sqlite3.connect('reports.db')
c = conn.cursor()
tree = ET.parse('example.nessus').getroot()
c.execute("CREATE TABLE IF NOT EXISTS reports (agent text, attachment text, bid text, cert text, cpe text, cve text, cvss3_base_score text, cvss3_temporal_score text, cvss3_temporal_vector text, cvss3_vector text, cvss_base_score text, cvss_temporal_score text, cvss_temporal_vector text, cvss_vector text, cwe text, description text, edb_id text, exploitability_ease text, exploit_available text, exploited_by_malware text, exploited_by_nessus text, exploit_framework_core text, exploit_framework_metasploit text, fname text, iava text, iavb text, in_the_news text, metasploit_name text, msft text, mskb text, osvdb text, patch_publication_date text, plugin_modification_date text, plugin_name text, plugin_output text, plugin_publication_date text, plugin_type text, risk_factor text, script_version text, see_also text, solution text, stig_severity text, synopsis text, tra text, unsupported_by_vendor text, vmsa text, vuln_publication_date text, xref text, zdi text)")

for reportitem in tree.iter('reportitem'):
	elems = [e for e in reportitem.iter() if len(e.text) > 1]
	marks = ', '.join("?" for e in elems)
	cols = ', '.join(e.tag.replace('-', '_') for e in elems)
	c.execute(f"INSERT INTO reports ({cols}) VALUES ({marks})", [e.text for e in elems])

for reportname in tree.iter('Report'):
	print(reportname.attrib)
	for reporthost in reportname.iter('ReportHost'):
		print(reporthost.tag)
		for hostproperties in reporthost.iter('HostProperties'):
			for tags in hostproperties.iter():
				print(tags.attrib)
				
				
conn.commit()
conn.close()

"""
Create ReportName table with relationship to ReportHost table
Create ReportHost table with relationship to HostItems table
Create HostItems table with relationship to ReportHost and ReportName tables
For ReportName:
	name=Report.nameflag
	For ReportHost:
		reportid=LastReportNameID
		name=ReportHost.nameflag
		For HostProperties:
			For X in taglist:
				columns+=tag.nameflag
			reportid=LastReportNameID
			reporthostid=LastReportHostID

ReportName table with name column and autoinc ID
ReportHost table with name column, autoinc ID column and reportid column from ReportName table
HostItemsID table with autoinc ID column, reportid column from ReportName table and ReportHost ID column from ReportHost table
"""
