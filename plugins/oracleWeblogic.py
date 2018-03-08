from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Oracle WebLogic Server%']
	name="Oracle WebLogic Server"
	description="The Oracle WebLogic web server software is used to host Java J2EE applications. A deployment of this software within the assessed environment appears to be missing software updates."
	risk_description="At least one installation of Oracle WebLogic server on a host was seen to be running on an outdated version. WebLogic has previously been affected by various instances of remote code exectuion, including a prominent issue relating to the Apache Commons Collections library as well as similar issues affecting other subcomponents and libraries used by WebLogic. Other previous issues knonw to affect older WebLogic versions have included unauthorised data modification and denial of service."
	recommendation="It is recommended that the deployment be upgraded to the most recent release made available by Oracle. Quarterly Critical Patch Updates (CPUs) are made available for Oracle products which are actively supported. Applying the most recent of these releases should address any issues affecting the identified deployments."
	notes="<url>https://www.oracle.com/technetwork/topics/security/alerts-086861.html#CriticalPatchUpdates</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices