from plugins import genFile

def gen(cb):
	appendices = []

	description=str()

	plugin_ids=["Cacheable HTTPS response"]
	name = "Cache-Control / Pragma"
	risk_description="The cache-control and pragma HTTP headers have not been correctly set by the web servers. This enables the user's browser and any proxies to cache the content of secure pages, which could enable sensitive information disclosure. Content that should only be accessible to an authenticated user can therefore be recovered after the session has terminated through the local cache or by pressing the 'back' button in the browser.\n\nThis was verified by viewing sensitive content, which should only be accessible to an authenticated user, through the cached web pages located in the 'Temporary Internet Files' in the system used by the tester."
	recommendation="Web servers should be configured to return caching directives instructing browsers not to store local copies of any sensitive data. This can be achieved using HTTP headers:\n\nSet the Cache-Control HTTP Header with no-cache, no-store, must-revalidate, private.\nSet the pragma HTTP Header with no-cache."
	notes="<url>https://www.owasp.org/index.php/Session_Management_Cheat_Sheet%23Web_Content_Caching</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids HSTS(BurpPlugin):
	plugin_ids=["Strict transport security not enforced"]
	name = "Strict-Transport-Security"
	risk_description="The application does not set the Strict-Transport-Security header. This header, once observed by a browser, prevents the browser from opening any subsequent connections to the server via unencrypted HTTP connections until the time in the max-age value provided by the header has expired. This prevents leakage of information, such as session cookies, via unencrypted connections."
	recommendation="Enable HTTP Strict Transport Security (HSTS) by adding a response header with the name 'Strict-Transport-Security' and the value 'max-age=expireTime', where expireTime is the time in seconds that browsers should remember that the site should only be accessed using HTTPS. Consider adding the 'includeSubDomains' flag if appropriate."
	notes="<url>https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids XFrameOptions(BurpPlugin):
	plugin_ids=["Frameable response (potential Clickjacking)"]
	name = "X-Frame-Options"
	risk_description="The web server does not set the X-Frame-Options HTTP header. It may be possible for a web page controlled by an attacker to load the content of this response within an IFrame on the attacker's page. This may enable a 'clickjacking' attack, in which the attacker's page overlays the target application's interface with a different interface provided by the attacker. By inducing victim users to perform actions such as mouse clicks and keystrokes, the attacker could cause them to unwittingly carry out actions within the application that is being targeted. This technique allows the attacker to circumvent defences against cross-site request forgery and may result in unauthorised actions."
	recommendation="Ensure the X-Frame-Options HTTP header is set on all web pages returned by the server. If the page will be framed by other pages on the server, then it should be set with SAMEORIGIN. Otherwise, if the page should never be framed, it should be set to DENY."
	notes="<url>https://www.owasp.org/index.php/Clickjacking</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids XXSSProtection(BurpPlugin):
	plugin_ids = ["Browser cross-site scripting filter misconfiguration"]
	name = "X-XSS-Protection"
	risk_description = "The web server does not set the X-XSS-Protection header. This header enables cross-site scripting (XSS) filters within certain web browsers that check if the URL contains possible harmful XSS payloads and if these are reflected in the response page. If such a condition is recognised, the injected code is prevented from executing."
	recommendation = "It is recommended that X-XSS-Protection header is set by the server with a value of '1; mode=block'"
	notes = "<url>https://www.owasp.org/index.php/OWASP_Secure_Headers_Project</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices