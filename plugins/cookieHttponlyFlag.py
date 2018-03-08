from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=["Cookie without HttpOnly flag set"]
	name="Cookies Not Set With HttpOnly Flag"
	description="Session cookies are used to track a user's application session and are typically used to check the permissions that a specific user session has within the application with regard to its available resources and functionality. By acquiring another user's session cookie value, an attacker may be able to connect to the application as that user.\n\nIf the acquired session cookie value relates to an authenticated session, then the attacker would have access to the application resources typically available to the targeted user.\n\nThe HttpOnly flag is available to be set on cookie values to prevent the cookie from being accessed by non-HTTP resources, such as JavaScript. By not setting the HttpOnly flag on a number of session cookies, sites are left potentially vulnerable to session-hijacking attacks through the exploitation of other application issues, such as cross-site scripting."
	risk_description="It has been noted that a cookie set by the application server does not have the HttpOnly flag set.\n\nIf a browser that supports HttpOnly detects a cookie containing the HttpOnly flag, and client-side script code attempts to read the cookie, the browser returns an empty string as the result.  This assists in protecting the logged-in user's session identifier and helps to prevent session-hijacking attacks."
	recommendation='Set the HttpOnly flag by including this attribute within the relevant Set-cookie directive.\n\nAlternatively, URL rewriting could be used, as is detailed in the following example.\n\n<rewrite>\n<outboundRules>\n<rule name="Add HttpOnly" preCondition="No HttpOnly">\n<match serverVariable="RESPONSE Set Cookie" pattern=".*" negate="false" />\n<action type="Rewrite" value="{R:0}; HttpOnly" />\n<conditions>\n</conditions>\n</rule>\n<preConditions>\n<preCondition name="No HttpOnly">\n<add input="{RESPONSE Set Cookie}" pattern="." />\n<add input="{RESPONSE Set Cookie}" pattern="; HttpOnly" negate="true" />\n</preCondition>\n</preConditions>\n</outboundRules>\n</rewrite>\n'
	notes="<url>http://www.owasp.org/index.php/HttpOnly</url>\n"
	notes+="<url>http://msdn.microsoft.com/en-us/library/ms972826</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices