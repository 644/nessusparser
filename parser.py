import xml.etree.ElementTree as ET
import sqlite3
## Run sql commands from here
conn = sqlite3.connect('reports.db')
## cursor for fetching results and error handling
c = conn.cursor()
## Open the nessus file and get the first block
tree = ET.parse('example.nessus').getroot()
## Messy but effective way of structuring the database
c.execute("CREATE TABLE IF NOT EXISTS reports (agent text, attachment text, bid text, cert text, cpe text, cve text, cvss3_base_score text, cvss3_temporal_score text, cvss3_temporal_vector text, cvss3_vector text, cvss_base_score text, cvss_temporal_score text, cvss_temporal_vector text, cvss_vector text, cwe text, description text, edb_id text, exploitability_ease text, exploit_available text, exploited_by_malware text, exploited_by_nessus text, exploit_framework_core text, exploit_framework_metasploit text, fname text, iava text, iavb text, in_the_news text, metasploit_name text, msft text, mskb text, osvdb text, patch_publication_date text, plugin_modification_date text, plugin_name text, plugin_output text, plugin_publication_date text, plugin_type text, risk_factor text, script_version text, see_also text, solution text, stig_severity text, synopsis text, tra text, unsupported_by_vendor text, vmsa text, vuln_publication_date text, xref text, zdi text)")

## Scan for the ReportItem tag and make it the new root
for ReportItem in tree.iter('ReportItem'):
	## Initialize empty arrays for cols and datas. Stops duplication
	cols = []
	datas = []
	## Adds each element's tag and text to their respective arrays
	for e in ReportItem.iter():
		if len(e.text) > 1:
			cols.append(e.tag)
			datas.append(e.text)
	## Generates question marks for each element the datas array to then be used in the INSERT query as a type of string expansion
	if len(datas) > 0:
		marklist = ["?"] * len(datas)
		marks = ', '.join(marklist)
	## Same with the cols array, except it uses %s for string expansion
	if len(cols) > 0:
		collist = ['%s'] * len(cols)
		colstrings = ', '.join(collist)
	## Replaces - with _ since - isn't allowed as a column name
	cols = [w.replace('-', '_') for w in cols]
	## Expands the insert query into a variable and executes
	insert = "INSERT INTO reports (%s) VALUES (%s)" % (colstrings, marks)
	c.execute(insert % (*cols,), (*datas,))
## Commits changes and exits
conn.commit()
conn.close()
