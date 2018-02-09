import xml.etree.ElementTree as ET
import sqlite3
conn = sqlite3.connect('reports.db')
c = conn.cursor()
tree = ET.parse('example.nessus').getroot()

"""This gets a unique list of all tags discovered within a reportitem tag
and then replace hyphens with underscores as to not violate SQL syntax"""
reportitem_tags = list(set([e.tag for e in tree.findall('.//ReportItem/*')]))
reportitem_tags = ', '.join(e.replace('-', '_') for e in reportitem_tags)

# Creates the first two tables if they don't already exist
c.execute(f"CREATE TABLE IF NOT EXISTS reportitems (report_id INTEGER, {reportitem_tags})");
c.execute("CREATE TABLE IF NOT EXISTS reports (report_id INTEGER PRIMARY KEY, report_name, reporthost_name, host_ip, netbios_name)")

"""This iters the report tag, then sets the report_name variable
 as the name attribute for each one discovered."""
for report in tree.iter('Report'):
	report_name = report.attrib["name"]
	
	"""This iters the reporthost tag, found within the report tag
	then sets the reporthost_name to name variable of the tag"""
	for reporthost in report.iter('ReportHost'):
		reporthost_name = reporthost.attrib["name"]
		
		"""This sets the host_ip variable to each hostproperties' child tag's <tag> text
		name attribute where the name attribute is host-ip, then does the same for
		the netbios_name variable, where the name attribute is netbios-name"""
		for hostproperties in reporthost.iter('HostProperties'):
			host_ip = [h.text for h in tree.findall('Report/ReportHost[@name="' + reporthost_name + '"]/HostProperties/tag[@name="host-ip"]')]
			netbios_name = [h.text for h in tree.findall('Report/ReportHost[@name="' + reporthost_name + '"]/HostProperties/tag[@name="netbios-name"]')]
			"""Sometimes the netbios-name is empty, and there must be data to insert
			so it sets it to none"""
			if len(netbios_name) < 1: netbios_name = ["NONE"]
			
			"""Finally the execution part is done, where all predefined variables are inserted
			to the reports database"""
			c.execute("INSERT INTO reports(report_name, reporthost_name, host_ip, netbios_name) VALUES(?, ?, ?, ?);", (report_name, reporthost_name, host_ip[0], netbios_name[0]))
			
			"""This gets the last row's ID from the report table, as that will be the desired
			ID for the reportitem report_id variable"""
			last_report_id = c.lastrowid
			
			"""This will scan the prediscovered reporthost tag for reportitems tags
			and for each reportitem it will define an elems array with the text for each tag
			within the reportitems tag as long as the text is longer than 1 character.
			
			It will then create a comma-separated list of question marks for each element in
			the elems array to be used for variable expansion later on.
			
			The cols variable will contain a comma-separated list of the tags found within the
			reportitems tag, and also replace hyphens with underscores as to not violate SQL syntax.
			
			Finally the execution is made, and the variables are entered"""
			for reportitem in reporthost.iter('ReportItem'):
				elems = [e for e in reportitem.iter() if len(e.text) > 1]
				marks = ', '.join("?" for e in elems)
				cols = ', '.join(e.tag.replace('-', '_') for e in elems)
				c.execute(f"INSERT INTO reportitems ({cols}, report_id) VALUES ({marks}, %d)" % last_report_id, [e.text for e in elems])

# Saving and closing the database
conn.commit()
conn.close()
