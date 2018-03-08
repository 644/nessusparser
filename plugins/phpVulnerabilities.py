from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['PHP % Multiple Vulnerabilities', 'PHP Unsupported Version Detection', 'PHP % <%','PHP PHP_RSHUTDOWN_FUNCTION Security Bypass','PHP < %']
	name="PHP Multiple Vulnerabilities"
	description="Older versions of PHP, a web application scripting language, were seen to be installed on the affected hosts. Newer revisions of the software are either released to addresses vulnerabilities or expand on the functionality of the language. As a result, each deployment may be vulnerable to a number of web application or service attack vectors that could be used to compromise a host or web application."
	risk_description="Potential vulnerabilities affecting the versions of PHP present on the affected hosts can include multiple buffer overflows, heap corruptions and flaws in several methods.\n\nExploitation of some of these issues requires an attacker to upload an arbitrary PHP script on to a server or to be able to manipulate several variables processed by some PHP functions (such as htmlentities()).\n\nThis finding is based on information returned by error pages, HTTP headers or default PHP deployment files that often contain the version number of the software."
	recommendation="It is recommended that PHP be upgraded to the latest version on the affected servers."
	notes=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices