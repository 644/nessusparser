from plugins import genParent

def gen(cb):
	appendices = []

	plugin_ids=["Cacheable HTTPS response"]
	plugin_ids+=["Strict transport security not enforced"]
	plugin_ids+=["Frameable response (potential Clickjacking)"]
	plugin_ids+=["Browser cross-site scripting filter misconfiguration"]

	description="HTTP Header Configuration\nThe following issues relate to the HTTP headers issued by the server. HTTP headers can be used to enable additional security funcitonality within client browsers that reduce the risks from certain classes of web application vulnerabilities."

	genParent.genr(cb, plugin_ids, description)
