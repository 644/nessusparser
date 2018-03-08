from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['IBM WebSphere Application Server %', 'IBM WebSphere Java Object Deserialization RCE']
	name="IBM WebSphere Application Server Vulnerabilities"
	description="The IBM WebSphere Application Server (WAS) software is used to host web sites and applications, allowing users to gain access to the relevant functionality provided by these services and their hosted resources. Deployments of this software appear to be missing software updates or present default resources that could be manipulated to affect the availability of the underlying host or allow access to information regarding the deployment."
	risk_description="The deployed versions of the IBM WAS web server are potentially affected by several vulnerabilities, including cross-site scripting, buffer overflow, local file inclusion and information disclosure, as well as issues affecting functionality provided by the Java Runtime Environment (JRE) and resources used by the services, each of which have since been addressed by updates/fix packs released by IBM but have not been applied to this installation. Without regular updates the services presented by this software present an elevated risk to them, the underlying host and any data it interacts with.  "
	recommendation="Affected hosts should be upgraded to the most recent, supported version of the IBM WAS branch (e.g. 7.x/8.x) in use using IBM provided Fix Packs. If the major branch in use is not supported seek an upgrade path  to a supported release."
	notes=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices