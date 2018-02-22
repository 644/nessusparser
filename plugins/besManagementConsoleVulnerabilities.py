from plugins import genFile

def gen(cb):
	plugin_ids=['BlackBerry Enterprise Service (BES) Management Console %']
	name="BlackBerry Enterprise Service (BES) Management Console"
	description="The BlackBerry Enterprise Service (BES) Management Console application is used to manage various aspects of a BES deployment (including users, devices, apps, and other components). Deployments of this software seen on hosts are running versions affected by known vulnerabilities."
	risk_description="The deployed versions of the BlackBerry Enterprise Service (BES) Management Console were identified from responses returned from the web management service. Such versions are reported to be affected by several vulnerabilities, including common web application attack vectors, such as cross-site scripting. These issues have since been addressed by updates released for BES 12."
	recommendation="Ensure the deployed BES version reflects the most recent, supported release and regularly check such deployments for new releases as part of an ongoing patching strategy."
	notes="<url>http://support.blackberry.com/kb/articleDetail?articleNumber=000038117</url>"
	notes+="\n<url>http://support.blackberry.com/kb/articleDetail?articleNumber=000038118</url>"
	notes+="\n<url>http://support.blackberry.com/kb/articleDetail?articleNumber=000038119</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
