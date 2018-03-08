from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['IBM Rational ClearQuest %']
	name="IBM Rational ClearQuest"
	description="Hosts have versions of the IBM Rational ClearQuest software installed that are affected by multiple vulnerabilities."
	risk_description="Authenticated assessment has identified that the version of IBM Rational ClearQuest installed on a number of hosts predates more recent releases. Such installations are affection by a number of web application attacks, including those associated with default/sample scripts (e.g. snoop), cross-site scripting vulnerabilities, information disclosure issues (Including those relating to passwords) and privilege escalation attacks as well as a number of issues for which details remain undisclosed."
	recommendation="Upgrade to the most recent, supported release of the IBM Rational ClearQuest branch in use."
	notes="<url>http://www-01.ibm.com/support/docview.wss?uid=swg21606319</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21606385</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21605840</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21605839</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21605838</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21606318</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg1PM15146</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg1PM01811</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg1PM20172</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg1PM22186</url>\n<url>http://www-01.ibm.com/support/docview.wss?uid=swg21470998</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices