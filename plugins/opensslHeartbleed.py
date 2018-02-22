from plugins import genFile

def gen(cb):
	plugin_ids=[73412]
	name="OpenSSL Heartbleed"
	description="Hosts presents at least one service using the OpenSSL library to enable TLS/SSL traffic encryption support. The version of the library identified in use is associated with a known issue which allows the contents of host memory to be read remotely by an unauthenticated user"
	risk_description="A number of hosts were seen to present at least one service which appear to be using a dated OpenSSL library associated with at least one known issue relating to a man-in-the-middle (MiTM) attack, based on a user's acceptance of a specially crafted handshake. This flaw could allow a MitM attacker to decrypt or forge SSL messages by telling the service to begin encrypted communications before key material has been exchanged, which causes predictable keys to be used to secure future traffic.\n\nVersions of OpenSSL affected by this issue are also commonly affected by a number of additional issues which permit data to be injected into existing SSL session, enables information disclosure or can facilitate denial-of-service and code execution attacks as a result of buffer overflow attacks."
	recommendation="This issue was fixed in more recent releases of OpenSSL, requiring any affected installations to be brought into line with the most recent, supported release.\n\nIf the affected service is provided as part of a third-party deployment (e.g. COTS product) then a vendor-specific solution may be required.\n\nAlternatively, recompile OpenSSL with the '-DOPENSSL_NO_HEARTBEATS' flag to disable the vulnerable functionality or remove the affected software if not in use."
	notes="<url>https://www.openssl.org/news/secadv/20140407.txt</url>"
	notes+="\n<url>http://heartbleed.com/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
