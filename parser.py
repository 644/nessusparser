from appJar import gui
import xml2sql as x
import sqlite3
from plugins import *
conn = sqlite3.connect('./reports.db')

def import_options(button):
	if button == 'ok1':
		try:
			x.xml2sqlite(app.getEntry('File'))
			print('\nSuccessfully converted %s to sqlite database' % app.getEntry('File'))
			app.removeAllWidgets()
			start_gui()
		except FileNotFoundError:
			print('File not found')
	else:
		exit()

def select_options(button):
	if button == 'ok2':
		cb_list = [cb for cb in app.getAllCheckBoxes() if app.getCheckBox(cb)]
		for cb in cb_list:
			telnet.gen(cb)
			activexControlsParent.gen(cb)
			activexControls.gen(cb)
			winlogonCachedPasswords.gen(cb)
			windowsUpdateReboot.gen(cb)
			windowsServer2003.gen(cb)
			webInternalIpDisco.gen(cb)
			vmwareVsphereUpdateManager.gen(cb)
			vmwareVcenter.gen(cb)
		print('Done')
		exit()
	else:
		exit()

app = gui('NessusParser', '335x235')
def start_gui():
	app.startTabbedFrame('TabbedFrame')
	app.startTab('Import')
	app.addLabel('file_dest', 'Click to open file')
	app.addFileEntry('File')
	row = app.getRow()
	app.addNamedButton('OK', 'ok1', import_options, row, 1)
	app.addNamedButton('Exit', 'exit1', import_options, row, 2)
	app.stopTab()

	app.startTab('Select')
	try:
		c = conn.cursor()
		c.execute('select DISTINCT reports.report_name from reports')
		for rc in c.fetchall():
			app.addCheckBox(rc[0])
	except sqlite3.OperationalError:
		app.addLabel('The database appears to be empty.\nImport a file first')
	
	row = app.getRow()
	app.addNamedButton('OK', 'ok2', select_options, row, 1)
	app.addNamedButton('Exit', 'exit2', select_options, row, 2)
	app.stopTab()
	app.stopTabbedFrame()

start_gui()
app.go()
