from plugins import genFile

def gen(cb):
	appendices = []

	description=str()
	## New plugins UntrustedSSLCertificate(VulnerabilityPlugin):
	plugin_ids=[57582, 51192]
	name="Untrusted SSL Certificate"
	risk_description="The X.509 certificate chain for this service is not signed by a recognised Certificate Authority (CA).  This prevents clients from positively identifying the remote server and may be exploited to carry out an SSL man-in-the-middle attack against the remote host."
	recommendation="It is recommended that a new certificate be obtained that has been signed by a trusted certificate authority."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Server_Certificate</url>"
	notes+="\n<url>https://www.globalsign.com/en/ssl-information-center/dangers-self-signed-certificates/</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLCertificateWithWrongHostname(VulnerabilityPlugin):
	plugin_ids=[45411]
	name="SSL Certificate with Wrong Hostname"
	risk_description="The commonName (CN) field of the certificate presented by each host is for a different hostname. This check is performed by automated software and may be a false positive. This is because the CN field is compared to the IP address of the host rather than its hostname. If an instance of this finding is not a false positive, then the continued use of this certificate encourages poor security awareness in staff and prevents the verification of a hosts authenticity."
	recommendation="Acquire a new certificate with the correct hostname to replace the existing one. This should be sourced from a trusted CA."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Server_Certificate</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins ExpiredSSLCertificate(VulnerabilityPlugin):
	plugin_ids=[15901]
	name="Expired SSL Certificate"
	risk_description="Hosts have been found to be presenting TLS/SSL enabled services using certificates that have expired. This configuration will cause certificate errors for clients connecting to the service and may prevent some applications from functioning. By providing such a certificate, the hosts are encouraging poor practice with regard to certificate security awareness, leaving users of these services prone to man-in-the-middle attacks."
	recommendation="Acquire a new, valid certificate to replace the existing one from a known and trusted CA."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Server_Certificate</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins WeakSSLCertificateinCertificateChain2048(VulnerabilityPlugin):
	plugin_ids=[60108,69551,73459]
	name="Weak SSL Certificate in Certificate Chain (< 2048 bits)"
	risk_description="An X.509 certificate sent by the remote host utilises a private key that is shorter than 2048 bits. Such keys are considered weak due to advances in available computing power decreasing the time required to factor cryptographic keys. Based on industry standards set by the Certification Authority/Browser (CA/B) Forum, certificates issued after January 1, 2014 must be at least 2048 bits long.\n\nSome browser SSL implementations may reject keys shorter than 2048 bits issued after January 1, 2014."
	recommendation="It is recommended that the SSL certificate for the remote host be reissued using a private key of greater length than 2048 bits."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://support.microsoft.com/en-gb/kb/2661254</url>"
	notes+="\n<url>https://www.rapid7.com/db/vulnerabilities/weak-crypto-key</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLCertificateSignedUsingaWeakHashingAlgorithm(VulnerabilityPlugin):
	plugin_ids=[35291]
	name="SSL Certificate Signed Using a Weak Hashing Algorithm"
	risk_description="Services use certificates that have each been signed using a cryptographically weak hashing algorithm (such as MD2, MD4, MD5 or SHA1). These signature algorithms are known to be vulnerable to collision attacks. In theory, a determined attacker may be able to leverage this weakness to generate another certificate with the same digital signature, which could allow them to masquerade as the affected service."
	recommendation="It is recommended that each affected certificate is reissued and signed using a strong cryptographic algorithm (e.g. SHA256)."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://technet.microsoft.com/library/security/961509</url>"
	notes+="\n<url>https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins WeakMediumCiphers(VulnerabilityPlugin):
	plugin_ids=[42873,26928,"SSL Null Cipher Suites Supported"]
	name="Weak / Medium SSL Ciphers Supported"
	risk_description="Hosts were seen that support the use of TLS/SSL ciphers that offer no encryption or weak / medium strength encryption (currently regarded as ciphers using keys shorter than 112 bits.) This reduces the computational effort required to decrypt TLS/SSL secured traffic and could allow an attacker to intercept traffic exchanged by the affected services. Note: This is considerably easier to exploit if the attacker is on the same physical network."
	recommendation="It is recommended that the configurations of all services utilising the TLS/SSL protocols are altered to use only strong ciphers.\n\nFor Windows hosts/services using SCHANNEL this will require Registry alterations to adjust the SCHANNEL supported ciphers."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://support.microsoft.com/en-gb/kb/245030</url>"
	notes+="\n<url>https://httpd.apache.org/docs/2.4/ssl/ssl_howto.html</url>"
	notes+="\n<url>https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Server_Protocol_and_Cipher_Configuration</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLRC4CipherSuitesSupported(VulnerabilityPlugin):
	plugin_ids=[65821]
	name="SSL RC4 Cipher Suites Supported"
	risk_description="Services support the use of the TLS/SSL protocols in order to encrypt service traffic. Within their current configuration, these services accept connections made using an RC4 cipher, which is considered to be cryptographically unsound. Due to flaws in its generation of random streams of bytes, the RC4 ciphers randomness is decreased as a result of a number of biases being introduced into the stream.\n\nAs a result, any plaintext value that is encrypted using this cipher and is repeatedly obtained by an attacker in its ciphertext form could enable them to derive the original plaintext. This process requires a significant number of ciphertexts to have been captured, reducing the likelihood of this issue being exploited."
	recommendation="Disable support for RC4 ciphers on each affected host/service.\n\nFor Windows hosts/services using SCHANNEL this will require Registry alterations to adjust the SCHANNEL supported ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser and web server support."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>http://httpd.apache.org/docs/trunk/ssl/ssl howto.html</url>"
	notes+="\n<url>https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/</url>"
	notes+="\n<url>http://www.isg.rhul.ac.uk/tls/</url>"
	notes+="\n<url>https://support.microsoft.com/en-gb/kb/245030</url>"
	notes+="\n<url>https://httpd.apache.org/docs/2.4/ssl/ssl_howto.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins AnonymousSSLCiphersPermitted(VulnerabilityPlugin):
	plugin_ids=[31705]
	name="Anonymous SSL Ciphers Permitted"
	risk_description="Hosts were seen to present TLS/SSL enabled services which support the use of anonymous ciphers. While this enables an administrator to set up a service that encrypts traffic without having to generate and configure certificates, it offers no way to verify a remote hosts identity and renders the service vulnerable to a Man-in-the-Middle attack."
	recommendation="If possible, reconfigure the affected application/host to prevent the use of anonymous ciphers."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Server_Protocol_and_Cipher_Configuration</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLTLSRenegotiationDenialofService(VulnerabilityPlugin):
	plugin_ids=[53491]
	name="SSL / TLS Renegotiation Denial of Service"
	risk_description="Services encrypt traffic using TLS / SSL and permit clients to renegotiate connections. The computational requirements for renegotiating a connection are asymmetrical between the client and the server, with the server performing several times more work. Each server does not appear to limit the number of renegotiations for a single TLS / SSL connection, this permits a client to open several simultaneous connections and repeatedly renegotiate them, possibly leading to a denial-of-service condition."
	recommendation="Vendor-supplied updates are usually required to remedy these issues. Fixes are available for Cisco devices, IBM products and Windows software. There are also cases were it is possible to reconfigure an affected host to prevent connecting clients from invoking connection renegotiations, such as in a Windows environment."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3555</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLVersion2and3ProtocolDetection(VulnerabilityPlugin):
	plugin_ids=[20007]
	name="SSL Version 2 and 3 Protocol Detection"
	risk_description="Services on the affected hosts accept connections encrypted using either SSL version 2.0 or version 3.0. Both versions are known to suffer from multiple cryptographic flaws which could enable an attacker to exploit these issues to conduct man-in-the-middle attacks or decrypt communications between the affected service and clients.\n\nNIST has determined that SSL 3.0 is no longer acceptable for secure communications. As of the date of enforcement found in PCI DSS v3.1, no versions of SSL will meet the PCI SSCs definition of strong cryptography."
	recommendation="Disable support for SSL version 2 and 3, replacing it with TLS (ideally TLS 1.2).\n\nThis will require Registry alterations within a Windows environment to adjust the SCHANNEL supported protocols or alterations to service configuration files for other services (e.g. Apache Web Server). See the Notes section for further details."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://httpd.apache.org/docs/2.4/ssl/ssl_howto.html</url>"
	notes+="\n<url>http://disablessl3.com/</url>"
	notes+="\n<url>https://support.microsoft.com/en-gb/kb/245030</url>"
	notes+="\n<url>https://support.microsoft.com/en-gb/kb/187498</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLDROWNAttack(VulnerabilityPlugin):
	plugin_ids=[89058]
	name="SSL DROWN Attack Vulnerability"
	risk_description="Services which support SSLv2 were identified. These may be affected by a vulnerability that allows a cross-protocol Bleichenbacher padding oracle attack known as DROWN (Decrypting RSA with Obsolete and Weakened eNcryption). This vulnerability exists due to a flaw in the Secure Sockets Layer Version 2 (SSLv2) implementation, and it allows captured TLS traffic to be decrypted. A man-in-the-middle attacker can exploit this to decrypt the TLS connection by utilising previously captured traffic and weak cryptography along with a series of specially crafted connections to an SSLv2 server that uses the same private key."
	recommendation="Disable SSLv2 and export grade cryptography cipher suites. Ensure that private keys are not used anywhere with server software that supports SSLv2 connections."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://drownattack.com/</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLTLSProtocolInitialisationVectorInformationDisclosure(VulnerabilityPlugin):
	plugin_ids=[58751,"SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)"]
	name="TLS/SSL BEAST Vulnerability"
	risk_description="TLS/SSL services on the hosts may be affected by an information disclosure issue due to a vulnerability in SSL 3.0 and TLS 1.0. Automated vulnerability assessment tools identified that these services respond to requests with a response that is not fragmented with an empty or one-byte record and has highlighted them as vulnerable.\n\nThis issue is directly related to the BEAST attack, which exploits the client-side iteration of this issue. The detection at server-side does not necessarily mean the services are vulnerable to the BEAST attack, because it exploits the vulnerability at client-side, and both SSL/TLS clients and servers can independently employ the split record countermeasure. Most modern browsers have now been patched against this issue, limiting its potential impact."
	recommendation="Review the configuration of the affected services so that they implement countermeasures for the BEAST attack (split records/empty fragments). This is typically controlled by settings of software such as OpenSSL or SCHANNEL.\n\nIf possible, remove all CBC ciphers from the accepted cipher suite list for each service or disable support for v1.0 of the TLS protocol."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>http://resources.infosecinstitute.com/beast-vs-crime-attack/</url>"
	notes+="\n<url>https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2011-3389</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins TransportLayerSecurityProtocolCRIMEVulnerability(VulnerabilityPlugin):
	plugin_ids=[62565]
	name="Transport Layer Security (TLS) Protocol CRIME Vulnerability"
	risk_description="Multiple SSL/TLS services are configured with at least one of two possible configurations that are known to be required for the CRIME attack: SSL / TLS compression is enabled or TLS advertises the SPDY protocol earlier than version 4.\n\nThis technique exploits web sessions protected by the Secure Sockets Layer and Transport Layer Security protocols when they use one of two data-compression schemes designed to reduce network congestion or the time it takes for webpages to load. Short for Compression Ratio Info-leak Made Easy, CRIME works only when both the browser and server support TLS compression or SPDY and can facilitate session hijacking.\n\nAs of September 2012, the Chrome, Firefox and Internet Explorer browsers were reported to mitigate the CRIME attack, reducing the risk posed by this finding."
	recommendation="If older browsers are still in use throughout the network, consider disabling TLS compression and / or the SPDY service on each of the affected hosts."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>http://resources.infosecinstitute.com/beast-vs-crime-attack/</url>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-4929</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLv3PaddingOracleOnDowngradedLegacyEncryptionVulnerability(VulnerabilityPlugin):
	plugin_ids=[78479]
	name="SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)"
	risk_description="Services are affected by a man-in-the-middle (MitM) information disclosure vulnerability known as POODLE. The vulnerability is due to the way SSL 3.0 handles padding bytes when decrypting messages encrypted using block ciphers in cipher block chaining (CBC) mode. MitM attackers can decrypt a selected byte of a cipher text in as few as 256 tries if they are able to force a victim application to repeatedly send the same data over newly created SSL 3.0 connections. As long as a client and service both support SSLv3, a connection can be rolled back to SSLv3, even if TLSv1 or newer is supported by the client and service.\n\nThe TLS Fallback SCSV mechanism prevents version rollback attacks without impacting legacy clients; however, it can only protect connections when the client and service support the mechanism. Sites that cannot disable SSLv3 immediately should enable this mechanism. This is a vulnerability in the SSLv3 specification, not in any particular SSL implementation."
	recommendation="Disable SSLv3 on each affected host. Services that must support SSLv3 should enable the TLS Fallback SCSV mechanism until SSLv3 can be disabled."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3566</url>"
	notes+="\n<url>https://www.openssl.org/news/secadv/20141015.txt</url>"
	notes+="\n<url>https://access.redhat.com/articles/1232123</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins TLSPaddingOracleOnDowngradedLegacyEncryptionVulnerability(VulnerabilityPlugin):
	plugin_ids=[80035]
	name="TLS Padding Oracle Information Disclosure Vulnerability (TLS POODLE)"
	risk_description="Several services are affected by a man-in-the-middle (MitM) information disclosure vulnerability known as POODLE. The vulnerability is due to the TLS server not verifying block cipher padding when using a cipher suite that employs a block cipher such as AES and DES. The lack of padding checking can allow encrypted TLS traffic to be decrypted. This vulnerability could allow for the decryption of HTTPS traffic by an unauthorised third party."
	recommendation="Vendor-issued updates will be required to address this issue. An alternative measure would be to move to utilising TLS 1.2 only on each service; however, this is likely to affect access to services from older clients."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://www.imperialviolet.org/2014/12/08/poodleagain.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SSLTLSRenegotiationHandshakesMiTMPlaintextDataInjection(VulnerabilityPlugin):
	plugin_ids=[42880]
	name="SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection"
	risk_description="Services encrypt traffic using TLS / SSL and permits clients to renegotiate connections after the initial handshake. A remote attacker may be able to leverage this issue to inject an arbitrary amount of plaintext into the beginning of the application protocol stream, which could facilitate man-in-the-middle attacks if the service assumes that the sessions before and after renegotiation are from the same client and merges them at the application layer.\n\nThis could lead to an attacker manipulating a valid users application session in order to perform actions as the authenticated user. One example would allow the injection of the start of a malicious HTTP request into the application stream that results in the users session cookie being appended to the request, authenticating the request as the user rather than the attacker."
	recommendation="Vendor-supplied updates are usually required to remedy these issues. Fixes are available for Windows software. There are also cases were it is possible to reconfigure an affected host to prevent connecting clients from invoking connection renegotiations, such as in a Windows environment."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>http://technet.microsoft.com/en-us/security/advisory/977377</url>"
	notes+="\n<url>http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3555</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins ExportWeakDHCiphers(VulnerabilityPlugin):
	plugin_ids=["SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)", "SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam),SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)"]
	name="Export Grade Ciphers/Weak Diffie Hellman Group (FREAK / Logjam)"
	risk_description="Services support connections made using EXPORT grade ciphers or with one or more Diffie-Hellman moduli that are 1024 bits or shorter. These ciphers use key lengths that are either weak by design and are therefore easier to break or now considered cryptographically unsound. This may allow an attacker to intercept or modify traffic as it passes over the network."
	recommendation="It is recommended that support for all EXPORT grade ciphers be disabled within the remote systems configuration. For OpenSSL, this can be achieved by specifying !EXPORT within the cipher definition string.\n\nIt is also recommended that a Diffie-Hellman modulus be generated that is a minimum length of 2048 bits. This can be achieved using the OpenSSL dhparam tool.\n\nFor IIS deployments, The \"Computer Configuration / Administrative Templates / Network / SSL Configuration Settings SSL Cipher Suite Order\" setting can be used to set a strong cipher suite order."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://www.openssl.org/news/secadv/20150108.txt</url>"
	notes+="\n<url>http://www.kb.cert.org/vuls/id/243585</url>"
	notes+="\n<url>https://weakdh.org/</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins SWEET32Ciphers(VulnerabilityPlugin):
	plugin_ids=[94437]
	name="64-bit Block Size Ciphers (SWEET32)"
	risk_description="The service supports the use of a block cipher with 64-bit blocks in one or more cipher suites and is therefore affected by a vulnerability known as SWEET32. A man-in-the-middle attacker who has sufficient resources can exploit this vulnerability, via a birthday attack, to detect a collision that leaks the XOR between the fixed secret and a known plaintext, allowing the disclosure of the secret text, such as secure HTTPS cookies, and possibly resulting in the hijacking of an authenticated session."
	recommendation="Reconfigure the affected service/application, if possible, to avoid use of all 64-bit block ciphers."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>https://sweet32.info/</url>"
	notes+="\n<url>https://www.openssl.org/blog/blog/2016/08/24/sweet32/</url>"
	
	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	## New plugins CertificateNullCharacter(VulnerabilityPlugin):
	plugin_ids=[42053]
	name="SSL Certificate Null Character Spoofing Weakness"
	risk_description="Services on hosts present an SSL certificate with a common name containing a Null character (\\x00) in it. This may indicate a compromise or that a program such as SSLsniff is spoofing the certificate in order to intercept the traffic via a Man-in-The-Middle (MiTM) attack.\n\nCertificates with such characters may exploit a bug contained in many different web browsers and other SSL-related products, in how they validate the common name of such a certificate."
	recommendation="A new certificate will need to be generated or obtained which does not contain a Null character in the CommonName value. For internal services, this would be expected to be source from an internal CA."
	notes="\n<bold_italic>"+name+"</bold_italic>"
	notes+="\n<url>http://thoughtcrime.org/papers/null-prefix-attacks.pdf</url>"
	
	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices