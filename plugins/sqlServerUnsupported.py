from plugins import genFile

def gen(cb):
	include_strings=["  Install path","  Installed version", "  Minimum supported version"]
	plugin_ids=['Microsoft SQL Server Unsupported Version Detection']	
	name="Unsupported Microsoft SQL Server"
	description="Installations of Microsoft SQL Server have been found that are no longer supported by Microsoft."
	risk_description="According to its version number, the installation of Microsoft SQL Server on the remote hosts is no longer supported. Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to remain vulnerable to any further security issues that are discovered within the product."
	recommendation="It is recommended that SQL Server is updated to its most recent available release. In some cases, SQL Server Express is bundled with other installed software, which requires an update to the packaging software."
	notes="<url>https://support.microsoft.com/en-gb/lifecycle/search?alpha=Microsoft%20SQL%20Server</url>"
	
	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
