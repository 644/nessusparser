import xml.etree.ElementTree as ET
import sqlite3

conn = sqlite3.connect('reports.db')
c = conn.cursor()
tree = ET.parse('report.xml').getroot()

c.execute("CREATE TABLE IF NOT EXISTS reports (ReportItem text, cwe text, description text)")
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
	insert = "INSERT INTO reports (%s) VALUES (%s)" % (datastrings, marks)
	c.execute(insert % (*cols,), (*datas,))

conn.commit()
conn.close()
