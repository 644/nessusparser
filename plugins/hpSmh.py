from plugins import genFile

def gen(cb):
	plugin_ids=['HP System Management Homepage%','Compaq WBEM%']
	name="HP System Management Homepage"
	description="Multiple servers within the tested network were found to be running the HP System Management Homepage or Compaq WBEM software. This is reportedly vulnerable to multiple issues that could potentially lead to remote code execution."
	risk_description="Several vulnerabilities have been reported in the installed versions of HP System Management Homepage software seen on a number of hosts. These include a variety of cross site scripting issues, potential buffer overflows and command injection vulnerabilities within the application. Prerequisites need to be met for a number of these vulnerabilities before they can be exploited, including authentication to the application. Additionally, no public exploits could be found for any buffer overflow issues, therefore the risk from this issue is believed to be reduced.\n\nIt should be noted that additional hosts may be present within the network that are also running more recent versions of HP System Management Homepage; however, these versions are not affected by any known vulnerabilities, so such deployments have not been included within this finding."
	recommendation="It is recommended that this service, if required, is updated to the latest version. If the service is not required, the software should be removed."
	notes="<url>http://h18013.www1.hp.com/products/servers/management/agents/index.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
