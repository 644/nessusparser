from plugins import genParent

def gen(cb):
	appendices = []

	plugin_ids=[57582, 51192]
	plugin_ids+=[45411]
	plugin_ids+=[15901]
	plugin_ids+=[60108,69551,73459]
	plugin_ids+=[35291]
	plugin_ids+=[42873,26928,"SSL Null Cipher Suites Supported"]
	plugin_ids+=[65821]
	plugin_ids+=[31705]
	plugin_ids+=[53491]
	plugin_ids+=[20007]
	plugin_ids+=[89058]
	plugin_ids+=[58751,'SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)']
	plugin_ids+=[62565]
	plugin_ids+=[78479]
	plugin_ids+=[80035]
	plugin_ids+=[42880]
	plugin_ids+=["SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)", 'SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)','SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)']
	plugin_ids+=[94437]
	plugin_ids+=[42053]

	description="TLS/SSL Multiple Issues\nA number of hosts have been found to be susceptible to several issues within services using the Transport Layer Security (TLS)/Secure Sockets Layer (SSL) protocol. These issues range from support for cryptographically weak ciphers that leave encrypted traffic vulnerable to decryption to certificate configuration errors that prevent a host's authenticity from being accurately determined, leaving traffic vulnerable to interception and redirection."

	genParent.genr(cb, plugin_ids, description)
