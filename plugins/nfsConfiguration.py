import sqlite3
import re
from plugins import genFile

def gen(cb):
	appendices = []

	name="NFS Service Configuration"
	local=False
	description="NFS (Network File System), is a client/server system that allows users to access files across a network and treat them as if they resided in a local file directory. This is accomplished through the processes of exporting (the process by which an NFS server provides remote clients with access to its files) and mounting (the process by which file systems are made available to the operating system and the user). Misconfigurations within such services can allow "
	risk_description=str()
	recommendation="Ensure that any affected services are filtered off from client devices and server hosts which do not require access to these shares and reconfigure each service to require authentication before mounting a share. This can be actioned using network or host based firewalls, as well as the hosts.deny file."
	notes="<url>http://www.tldp.org/HOWTO/NFS-HOWTO/server.html</url>"
	notes+="\n<url>http://www.centos.org/docs/5/html/Deployment Guide-en-US/s1-nfs-security.html</url>"
	notes+="\n<url>https://help.ubuntu.com/community/NFSv4Howto</url>"

	plugin_ids = ['NONE']

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'NFS Exported Share Information Disclosure'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'NFS Exported Share Information Disclosure'")
	export_results = c.fetchall()
	c.close()

	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	try:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name,reportitems.mskb from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'NFS Shares World Readable'")
	except sqlite3.OperationalError:
		c.execute("select reports.report_id,reports.reporthost_name,reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name == 'NFS Shares World Readable'")
	read_results = c.fetchall()
	c.close()
	
	export_hosts = []
	read_hosts = []
	for x in export_results:
		if x[1]:
			export_hosts.append(x[1])
		else:
			export_hosts.append(x[2])

	for x in read_results:
		if x[1]:
			read_hosts.append(x[1])
		else:
			read_hosts.append(x[2])

	affected_hosts = export_hosts + read_hosts

	export=False
	read=False

	if len(export_results) > 0:
		export=True
		description+="the disclosure of shares made available by the service"
		risk_description+="NFS services were seen to permit non-privileged (root) users to mount at least one of the shared directories that they export. An attacker utilising this behaviour would then be permitted to browse the directory contents of the share and potentially gain access to files contained within these shares.\n\nThe impact and therefore the risk presented by this finding is heavily dependant on the permissions set on the files contained within these shares, as write access to these files/directories could permit the upload of malicious files or alteration of existing files, whilst read access would permit an attacker to read the contents of potentially sensitive files."
	
	if len(read_results) > 0:
		if export:
			description+=" or read access to hosted shares/their content"
			self.risk_description+="\n\nA number of these services permit read-only access to users mounting their available shares. Whilst this prevents users from uploading potentially malicious files or replacing existing file contents with redundant or malicious data, it can permit unauthorised users to retrieve files from the service and view their contents. Should the contents of such files be sensitive e.g. database or configuration backups, this could result in the disclosure of sensitive information or facilitate further attacks against other network assets."
		else:
			description+=" read access to hosted shares/their content"
			risk_description+="NFS services were seen to permit read-only access to users mounting their available shares. Whilst this prevents users from uploading potentially malicious files or replacing existing file contents with redundant or malicious data, it can permit unauthorised users to retrieve files from the service and view their contents. Should the contents of such files be sensitive e.g. database or configuration backups, this could result in the disclosure of sensitive information or facilitate further attacks against other network assets."
	description+="."

	ap = genFile.gen_document(cb, name, description, risk_description, recommendation, notes, affected_hosts)

	if not ap is None:
		appendices += ap

	if appendices:
		return appendices
