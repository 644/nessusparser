from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Apache 1.% Multiple Vulnerabilities']
	name="Apache Web Server 1.3.x Multiple Vulnerabilities"
	description="The Apache web server (HTTPD) software is used to host web sites and applications, allowing users to gain access to the relevant functionality provided by these services and their hosted resources. A deployment of this software on a host appears to be missing software updates or presents default resources that could be manipulated to affect the availability of the underlying host or allow access to information regarding the deployment."
	risk_description="The deployed version of the Apache HTTP 1.3.x web server is potentially affected by several vulnerabilities, including cross-site scripting, buffer overflow, local file inclusion and information disclosure, which have since been addressed by updates to the Apache HTTPD 1.3.x branch. The existence of several of these vulnerabilities depends on the presence of the specific Apache modules that are affected and on the current installation not having received any backported patches, which is typical practice for software managed as part of other repositories."
	recommendation="If this deployment is not running a version which utilises backported security updates then it should be upgraded to the most recent version of the Apache 1.3.x distribution. It should be noted that the final version of this branch has been made availabled, indicating that no future updates will be made to it.\n\nAs these issues often only affect deployments using specific Apache modules, a review of each Apache server and the modules it uses is recommended.\n\nThis deployment may also be part of a wider software installation provided by a third party. In this case, guidance for updating the software should be sought from the relevant vendor."
	notes="<url>http://httpd.apache.org</url>\n<url>http://httpd.apache.org/security/vulnerabilities_13.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices