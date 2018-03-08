from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Apache Tomcat % < %', 'Apache Tomcat < %', 'Apache Tomcat servlet/JSP container default files']
	name="Apache Tomcat Multiple Vulnerabilities"
	description="The Apache Tomcat web server software is used to host Java Web Applications, web sites and applications. A deployment of this software on a host appears to be missing software updates."
	risk_description="The deployed versions of the Apache Tomcat web server are potentially affected by several vulnerabilities, including cross-site scripting, memory leaks, buffer overflow and information disclosure, which have since been addressed by subsequent updates. Additionally, default content provided by versions of this software is known to present security issues, such as cross-site scripting."
	recommendation="It is recommended that the deployment be upgraded to the most recent version of the Apache Tomcat software. All content hosted by the service should also be reviewed and removed if not required.\n\nThis deployment may also be part of a wider software installation provided by a third party. In this case, guidance for updating the software should be sought from the relevant vendor."
	notes="<url>https://tomcat.apache.org/security-7.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices