from plugins import genFile

def gen(cb):
	plugin_ids=["SSL cookie without Secure flag set"]
	name="Cookies Not Set With Secure Flag"
	description="Secure is an additional flag included in a Set-Cookie HTTP response header. Using the Secure flag when generating a cookie helps mitigate the risk of interception of cookies sent over encrypted communications, as otherwise they could be accessed outside of the Secure session."
	risk_description="If the Secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic.\n\nIf the Secure flag is not set, then the cookie will be transmitted in cleartext whenever the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site.\n\nEven if the domain which issued the cookie does not host any content that is accessed over HTTP, an attacker may be able to use links of the form http://example.com:443/ to perform the same attack."
	recommendation="The Secure flag should be set on all cookies that are used for transmitting sensitive data when accessing content over HTTPS. If cookies are used to transmit session tokens, then areas of the application that are accessed over HTTPS should employ their own session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications."
	notes="<url>https://www.owasp.org/index.php/SecureFlag</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
