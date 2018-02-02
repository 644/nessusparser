import xml.etree.ElementTree as ET
import sqlite3
conn = sqlite3.connect('reports.db')
c = conn.cursor()
tree = ET.parse('example.nessus').getroot()
c.execute("CREATE TABLE IF NOT EXISTS reports (agent text, attachment text, bid text, cert text, cpe text, cve text, cvss3_base_score text, cvss3_temporal_score text, cvss3_temporal_vector text, cvss3_vector text, cvss_base_score text, cvss_temporal_score text, cvss_temporal_vector text, cvss_vector text, cwe text, description text, edb_id text, exploitability_ease text, exploit_available text, exploited_by_malware text, exploited_by_nessus text, exploit_framework_core text, exploit_framework_metasploit text, fname text, iava text, iavb text, in_the_news text, metasploit_name text, msft text, mskb text, osvdb text, patch_publication_date text, plugin_modification_date text, plugin_name text, plugin_output text, plugin_publication_date text, plugin_type text, risk_factor text, script_version text, see_also text, solution text, stig_severity text, synopsis text, tra text, unsupported_by_vendor text, vmsa text, vuln_publication_date text, xref text, zdi text)")
for ReportItem in tree.iter('ReportItem'):
	cols = []
	datas = []
	for e in ReportItem.iter():
		if len(e.text) > 1:
			cols.append(e.tag)
			datas.append(e.text)
	if len(datas) > 0:
		marklist = ["?"] * len(datas)
		marks = ', '.join(marklist)
	if len(cols) > 0:
		datalist = ['%s'] * len(cols)
		datastrings = ', '.join(datalist)
	cols = [w.replace('-', '_') for w in cols]
	insert = "INSERT INTO reports (%s) VALUES (%s)" % (datastrings, marks)
	c.execute(insert % (*cols,), (*datas,))
conn.commit()
conn.close()
