from plugins import genFile

def gen(cb):
	appendices = []
	
	plugin_ids=[11213]
	name="HTTP TRACE Method"
	description="A web debugging function is enabled on a number of web servers. This HTTP method is often used by developers in order to debug issues with web applications, but has been associated with web attack vectors in the past, including those which can bypass the protection offered by the use of httpOnly cookies."
	risk_description="The affected web servers appear to support the HTTP TRACE method. TRACE is a method that is used to debug web server connections and can provide valuable information to application developers."
	risk_description+="\n\nThe TRACE method has also historically been utilised in web-based attacks known as cross-site tracing and should be used with caution. The HTTP TRACE method replies to any request, together with all the headers in the response, including the cookie header. If session cookies do not have the httpOnly flag set, they may be vulnerable to session-hijacking attacks; the httpOnly flag prevents this by blocking access to the value of the cookie. With the TRACE method enabled, an attacker can send a request, e.g. XMLHttprequest (AJAX), to the target server."
	risk_description+="\n\nThe user's web browser will attach the cookies to the request and the server will echo them in its response, thus defeating the httpOnly flag. The risk may be considered low, as many browsers simply disallow sending requests with TRACE method. A risk still exists, however, as plugins that receive cookies from the browser, such as Flash, Silverlight and Java, may use them for sending TRACE requests."
	risk_description+="\n\nThe risk given to this issue is Low because currently most browsers block TRACE in an XMLHttpRequest (XHR), which would need to be made by a client. Still, there are possible attacks leveraging corner case situations, but these are difficult to mount. A complete explanation is presented in the referenced links."
	recommendation="If not required by development users, disable this method. For Apache servers, edit the /etc/apache2/conf.d/security file:\n\nDisable TRACE:\nTraceEnable Off\nReload Apache:\n/etc/init.d/apache2 reload\n\nFor IIS, change the EnableTraceMethod entry in the following Registry Path to a value of 0:\nHKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3S"
	notes="<bold>Bypassing httpOnly Using TRACE Method</bold>"
	notes+="\n<url>http://jeremiahgrossman.blogspot.ro/2007/04/xst-lives-bypassing-httponly.html</url>"
	notes+="\n\n<bold>Cross-Site Tracing</bold>"
	notes+="\n<url>https://www.owasp.org/index.php/Cross Site Tracing</url>"
	notes+="\n\n<bold>Test for HTTP TRACE Method</bold>"
	notes+="\n<url>https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST %28OWASP-CM-008%29</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices
