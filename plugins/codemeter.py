from plugins import genFile

def gen(cb):
	plugin_ids=['CodeMeter < 5.20 Local Privilege Escalation Vulnerability']
	name="CodeMeter Privilege Escalation"
	description="The Apache web server (HTTPD) software is used to host web sites and applications, allowing users to gain access to the relevant functionality provided by these services and their hosted resources. A deployment of this software on a host appears to be missing software updates or presents default resources that could be manipulated to affect the availability of the underlying host or allow access to information regarding the deployment."
	risk_description="Based on the self-reported version recovered from responses from CodeMeter WebAdmin server instances, a number of deployments are running versions prior to 5.20a (5.20.1458.500). Such versions are affected by insecure read/write permissions for the 'codemeter.exe' service which a local attacker can exploit to gain elevated privileges using a crafted file.\n\nThis issue was identified remotely during the assessment and requires access to the underlying host in order to leverage it, limiting its immediate risk."
	recommendation="This issue was addressed in CodeMeter version 5.20a (5.20.1458.500), so upgrading each deployment to the most recent release should address this issue.\n\nAlterantively, permissions set on the 'codemeter.exe' service executable and service could be revised to prevent non-privileged users from altering the service configuration or replacing the executable."
	notes="<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8419</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
