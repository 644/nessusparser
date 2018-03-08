from appJar import gui
import xml2sql as x
import sqlite3
from plugins import *
from plugins import genFile
conn = sqlite3.connect('./reports.db')

genrFiles = [microsoftPatching, telnet, activexControlsParent, activexControls, winlogonCachedPasswords, windowsUpdateReboot, windowsServer2003, webInternalIpDisco, vmwareVsphereUpdateManager, vmwareVcenter, vmwareEsxi, unquotedServicePaths, sslTlsMultipleIssuesParent, sslTlsMultipleIssues, sshV1, sqlServerUnsupported, smtpExpnVrfy, smb, sambaVersionVulnerabilities, anonymousFtp, apache13Vulnerabilities, apache22Vulnerabilities, apacheTomcat, besManagementConsoleVulnerabilities, buildReviewAixParent, buildReviewAix, buildReviewRhelParent, buildReviewRhelWip, buildReviewWindowsParent, buildReviewWindows, chargenDos, codemeter, cookieHttponlyFlag, cookieSecureFlag, dnsDynRecord, dnsIssuesParent, dnsIssues, eiqEsaVulnerabilities, firebirdDefaultCreds, ftpCleartext, hpSmh, httpHeadersParent, httpHeaders, ibmBigfix, ibmClearquest, ibmDb2105, ibmDb297, ibmGcmFirmware, ibmTivoliStorageServer, ibmWasVunerabilities, ibmWebsphere, imagemagick, insecureServicePermissions, ldapNullBase, linuxKernelTcpSeq, lmNtlm, mcafeeVse, microsoftMalware, microsoftScep, microsoftSmbv1, miniupnpVersion1, msXmlParsers, ntpMultipleIssuesParent, ntpMultipleIssues, opensshMaxAuth, opensshVulnerabilities, openssl097, openssl098, openssl101, opensslCcs, opensslHeartbleed, oracleDatabase, oracleGlassfish, oracleTnsListenerPoisoning, oracleWeblogic, outdatedSoftwareParent, outdatedSoftware, phpVulnerabilities, rlogin, rServices, sambaBadlock]

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
			appendix = []
			for fg in genrFiles:
				appendices = fg.gen(cb)
				if not appendices is None:
					appendix += appendices
				
			genFile.appendGen(cb, appendix)
			print(cb, 'report finished')
		exit()
	else:
		exit()

app = gui('NessusParser', '378x264')
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
