from plugins import genFile

def gen(cb):
	child_module = str()

	plugin_ids=[10759]
	name="Web Server Internal IP Disclosure"
	description="Web servers have been identified which leak a private IP address through their returned HTTP headers."
	risk_description="Sending HTTP requests of a specific format (e.g. a request missing the Host header, such as \"GET / HTTP/1.0\") to web servers resulted in private IP addresses being returned within the Location or Content-Location header within the HTTP response. This may expose internal IP addresses that are usually hidden or masked behind a Network Address Translation (NAT) Firewall or proxy server, providing an attacker with additional knowledge about an organisation's networks.\n\nThis issue is known to affect older variations of Microsoft IIS its default configuration, as well as other web servers, web applications, web proxies, load balancers, and through a variety of misconfigurations related to redirection."
	recommendation="Vendor-specific solutions may be available through updates for the underlying web server software. Alternative solutions may include configuring software/application logic to manually set header values being sent with each HTTP response."
	notes="<url>https://support.microsoft.com/en-gb/kb/967342</url>"
	notes+="<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2000-0649</url>"
	
	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes, child_module)
