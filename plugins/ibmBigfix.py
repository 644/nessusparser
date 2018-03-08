from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['IBM BigFix Platform%','IBM BigFix Server%']
	name="IBM BigFix Server"
	description="Hosts have a version of an infrastructure management application, IBM BigFix, that is affected by multiple issues."
	risk_description="The IBM BigFix Server software running on hosts is version #######. As such each are susceptible to multiple issues within their application logic, primarily relating to reflected cross-site scripting (XSS) attacks, which presented a limited risk and a denial-of-service issue in the BES Root Server and BES Relay due to improper handling of user-supplied input. An adjacent attacker can exploit this, via a specially crafted request, to cause the system to crash.\n\nThe current software version is also reported to be affected by several vulnerabilities within the bundled version of OpenSSL; however, the present version of this library could not be determined."
	recommendation="Upgrade to the latest, supported IBM BigFix Server version."
	notes="<url>http://www-01.ibm.com/support/docview.wss?uid=swg21985734</url>"
	notes+="\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21985743</url>"
	notes+="\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21996348</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices