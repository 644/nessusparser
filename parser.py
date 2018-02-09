import xml.etree.ElementTree as ET
import sqlite3
conn = sqlite3.connect('reports.db')
c = conn.cursor()
tree = ET.parse('example.nessus').getroot()
reportitem_tags = list(set([e.tag for e in tree.findall('.//ReportItem/*')]))
reportitem_tags = ', '.join(e.replace('-', '_') for e in reportitem_tags)
c.execute(f"CREATE TABLE IF NOT EXISTS reportitems (report_id INTEGER, {reportitem_tags})");
c.execute("CREATE TABLE IF NOT EXISTS reports (report_id INTEGER PRIMARY KEY, report_name, reporthost_name, host_ip, netbios_name)")

for report in tree.iter('Report'):
	report_name = report.attrib["name"]
	for reporthost in report.iter('ReportHost'):
		reporthost_name = reporthost.attrib["name"]
		for hostproperties in reporthost.iter('HostProperties'):
			host_ip = [h.text for h in tree.findall('Report/ReportHost[@name="' + reporthost_name + '"]/HostProperties/tag[@name="host-ip"]')]
			netbios_name = [h.text for h in tree.findall('Report/ReportHost[@name="' + reporthost_name + '"]/HostProperties/tag[@name="netbios-name"]')]
			if len(netbios_name) < 1: netbios_name = ["NONE"]
			c.execute("INSERT INTO reports(report_name, reporthost_name, host_ip, netbios_name) VALUES(?, ?, ?, ?);", (report_name, reporthost_name, host_ip[0], netbios_name[0]))
			last_report_id = c.lastrowid
			for reportitem in reporthost.iter('ReportItem'):
				elems = [e for e in reportitem.iter() if len(e.text) > 1]
				marks = ', '.join("?" for e in elems)
				cols = ', '.join(e.tag.replace('-', '_') for e in elems)
				c.execute(f"INSERT INTO reportitems ({cols}, report_id) VALUES ({marks}, %d)" % last_report_id, [e.text for e in elems])

conn.commit()
conn.close()
