import xml.etree.ElementTree as ET
import sqlite3
conn = sqlite3.connect('reports.db')
c = conn.cursor()
tree = ET.parse('report.xml').getroot()
c.execute("CREATE TABLE IF NOT EXISTS reports (ReportItem text, cwe text, description text)")

inserts = []
for ReportItem in tree.iter('ReportItem'):
	for e in ReportItem.iter():
		fields = "\'" + '\', \''.join(e.tag) + "\'"
		data = "\'" + '\', \''.join(e.text) + "\'"
		
		if len(e.text) > 3:
			marklist = ["?"] * len(e.text)
			marks = ', '.join(marklist)
			print(e.text)
			c.execute("INSERT INTO reports (cwe) VALUES (?)", (e.text,))

conn.commit()
conn.close()
