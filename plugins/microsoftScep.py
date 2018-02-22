from plugins import genFile

def gen(cb):
	plugin_ids=['Microsoft Forefront Endpoint Protection / System Center Endpoint Protection / Anti-malware Client Detection and Status']
	include_strings=["  Product name","  Path","  Version","  Engine version","  Antivirus signature version","  Antispyware signature version"]
	name="Microsoft Endpoint Protection"
	description="A number of Windows hosts have been identified with variant of Microsoft endpoint protection software (e.g. Frontfront/System Center Endpoint Protection) installed. Observations indicate that these deployments are running unsuitable configurations, weakening the security posture of each affected host."
	risk_description="Hosts were found to have issues within the configuration of their Microsoft endpoint protection software installations. A lack of regular updates for the antivirus databases in use by these deployments are seen to prevent hosts from being able to detect more recently identified malicious content/activity and thus leaving them more susceptible to compromise in the event malicious content is accessed on the host."
	recommendation="Ensure each endpoint protection deployment is kept in line with the most recent definition data releases and ensure they are configured to retrieve signature updates regularly."
	notes="<url>https://technet.microsoft.com/en-us/library/hh508836.aspx</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
