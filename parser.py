import xml.etree.ElementTree as ET
import sqlite3
from appJar import gui
from shutil import copyfile
conn = sqlite3.connect('reports.db')

def xml2sqlite(dest_file):
	conn = sqlite3.connect('reports.db')
	c = conn.cursor()
	tree = ET.parse(dest_file).getroot()
	reportitem_tags = list(set([e.tag for e in tree.findall('.//ReportItem/*')]))
	reportitem_tags = ', '.join(e.replace('-', '_') for e in reportitem_tags)

	c.execute(f"CREATE TABLE IF NOT EXISTS reportitems (plugin_id TEXT, report_id INTEGER, {reportitem_tags})");
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
					plugin_id = reportitem.attrib["pluginID"]
					elems = [e for e in reportitem.iter() if len(e.text) > 1]
					marks = ', '.join("?" for e in elems)
					cols = ', '.join(e.tag.replace('-', '_') for e in elems)
					try:
						c.execute(f"INSERT INTO reportitems ({cols}, plugin_id, report_id) VALUES ({marks}, %s, %d)" % (plugin_id, last_report_id), [e.text for e in elems])
					except sqlite3.OperationalError:
						print("Could not add to db")

	conn.commit()
	conn.close()
	print("Successfully converted %s to sqlite database" % dest_file)

def import_options(button):
	if button == "OK":
		xml2sqlite(app.getEntry("File"))
	else:
		exit()

def select_options(button):
	if button == "OK":
		cb_list = [cb for cb in app.getAllCheckBoxes() if app.getCheckBox(cb)]
		for cb in cb_list:
			c = conn.cursor()
			c.execute("select reports.host_ip from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name LIKE 'Unencrypted Telnet Server' AND reports.report_name = ?", [cb])
			copyfile('plugins/telnet-services.txt', './' + cb + '.txt')
			with open('./' + cb + '.txt', "a") as t_file:
				[ t_file.write(str(append_line[0] + '\n')) for append_line in c.fetchall() ]
		print("Done")
		exit()
	else:
		exit()

def first_press(button):
	if button == "Import":
		app.removeAllWidgets()
		app.addLabel("title", "Enter the file destination")
		app.setLabelBg("title", "white")
		app.setLabelFg("title", "white")
		app.addFileEntry("File")
		app.setFocus("File")
		app.addButtons(["OK", "Exit"], import_options)
	elif button == "Select":
		c = conn.cursor()
		app.removeAllWidgets()
		c.execute('select DISTINCT reports.report_name from reports')
		for rc in c.fetchall():
			app.addCheckBox(rc[0])
		app.addButtons(["OK", "Exit"], select_options)
	else:
		exit()

app = gui("NessusParser", "335x235")
app.setBg("white")
app.addButtons(["Import", "Select", "Exit"], first_press)
app.go()
