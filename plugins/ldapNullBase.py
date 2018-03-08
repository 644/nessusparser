from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=[10722]
	name="LDAP NULL BASE Search Access"
	description="LDAP services support requests with NULL base objects, which can be used to extract information about the directory structure."
	risk_description="LDAP server services were identified which support search requests with a NULL, or empty, base object. This configuration allows information to be retrieved from the services without any prior knowledge of the directory structure. Coupled with a NULL BIND, an anonymous user may be able to query the service and recover information from the directory (e.g. users, address details etc).\n\nIt should be noted that valid reasons to allow queries with a NULL base do exist. The most recent iteration of the LDAP protocol, version 3, provides access to the root DSA-Specific Entry (DSE), with information about the supported naming context, authentication types, and the like. It also means that legitimate users can find information in the directory without any prior knowledge of its structure."
	recommendation="If the affected LDAP servers support a version of the LDAP protocol prior to v3, consider disabling NULL BASE queries."
	notes="<url>http://support.microsoft.com/kb/837964</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices