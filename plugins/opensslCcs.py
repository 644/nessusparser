from plugins import genFile

def gen(cb):
	plugin_ids=[77200]
	name="OpenSSL ChangeCipherSpec"
	description="Hosts present at least one service using the OpenSSL library to enable TLS/SSL traffic encryption support. The versions of the library identified in use are associated with at least one known issue which could permit a man-in-the-middle (MiTM) attack."
	risk_description="A number of hosts were seen to present at least one service which appear to be using a dated OpenSSL library associated with at least one known issue relating to a man-in-the-middle (MiTM) attack, based on a user's acceptance of a specially crafted handshake. This flaw could allow a MitM attacker to decrypt or forge SSL messages by telling the service to begin encrypted communications before key material has been exchanged, which causes predictable keys to be used to secure future traffic.\n\nVersions of OpenSSL affected by this issue are also commonly affected by a number of additional issues which permit data to be injected into existing SSL session, enables information disclosure or can facilitate denial-of-service and code execution attacks as a result of buffer overflow attacks."
	recommendation="This issue was fixed in updated releases of OpenSSL 0.9.8, 1.0.0 and 1.0.1. Each affected installation should be brought into line with the most recent, supported release.\n\nIf an affected service is provided as part of a third-party deployment (e.g. COTS product) then a vendor-specific solution may be required.\n\nAlternatively remove the affected software if not in use."
	notes="<url>https://www.openssl.org/news/secadv/20140605.txt</url>"
	notes+="\n<url>http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
