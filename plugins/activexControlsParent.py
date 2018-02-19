from plugins import genFile

def gen(cb):
	risk_description = str()
	recommendation = str()
	
	plugin_ids="Activex Controls"
	name="ActiveX Controls"
	description="Hosts have been identified with vulnerable ActiveX controls installed. Hosts would be at risk of remote compromise if a user was tricked into accessing malicious resources."
	notes="<url>https://support.microsoft.com/kb/240797</url>\n\n"
	child_module="activex_controls"
	
	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes, child_module)
