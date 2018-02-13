from shutil import copyfile
from appJar import gui
import sqlite3
import xml2sql as x
conn = sqlite3.connect('reports.db')

def import_options(button):
	if button == "OK":
		x.xml2sqlite(app.getEntry("File"))
		print("Successfully converted %s to sqlite database" % app.getEntry("File"))
	else:
		exit()

def select_options(button):
	if button == "OK":
		cb_list = [cb for cb in app.getAllCheckBoxes() if app.getCheckBox(cb)]
		for cb in cb_list:
			c = conn.cursor()
			c.execute("select reports.host_ip from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name LIKE 'Unencrypted Telnet Server' AND reports.report_name = ?", [cb])
			all_rows = c.fetchall()
			if len(all_rows) > 0:
				copyfile('plugins/telnet-services.txt', './' + cb + '.txt')
				with open('./' + cb + '.txt', "a") as t_file:
					[ t_file.write(str(append_line[0] + '\n')) for append_line in all_rows ]
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
