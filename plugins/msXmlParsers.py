from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Microsoft XML Parser (MSXML) and XML Core Services Unsupported']
	include_strings=["    Path","    File version","    XML Core version"]
	name="Unsupported Microsoft XML Parser"
	description="Multiple hosts are running Microsoft Windows with at least one version of Microsoft XML parsers installed that is no longer supported."
	risk_description="Each of the affected Windows hosts contains at least one unsupported version of the Microsoft XML Parser (MSXML) or XML Core Services. Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities or have new issues identified in the future.\n\nThe likelihood of exploiting issues within these parsers is seen to be limited as it requires applications which utilise them to make use of specific vulnerable functionality. This reduces the immediate risk seen to be presented by these installations."
	recommendation="Upgrade the installed MSXML parsers to a supported release, the most recent release currently being version 6.0. This upgrade may affect the functionality of applications which rely on these XML parsers.\n\nThis is often bundled with other software which relies on its provided functionality, making addressing this issue without impacting applications difficult. Common exploitation vectors require crafted XML content to be supplied to specific methods/functions within the XML parser, which is seen to add further complexity to leveraging issues in this software, reducing the risk it presents."
	notes="<url>http://support.microsoft.com/en-us/kb/269238</url>\n"
	notes+="<url>https://msdn.microsoft.com/en-us/library/jj152146(v=vs.85).aspx</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices