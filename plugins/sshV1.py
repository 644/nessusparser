from plugins import genFile

def gen(cb):
	plugin_ids=['SSH Protocol Version 1 Session Key Retrieval']
	name="SSH Protocol Version 1 Support"
	description="Secure Shell services are used to provide secure remote access to network-connected hosts to allow administrative actions to be performed remotely while ensuring the confidentiality of the service traffic. Historical versions of the SSH protocol suffer from cryptographic flaws, reducing the computational effort required to decrypt communications secured using older protocols. Successful decryption of traffic could facilitate a host compromise."
	risk_description="The SSH service on these devices support connections made using version 1.5 of the SSH protocol. This protocol has known cryptographic flaws that affect the encryption mechanism used to secure the service traffic. As a result, the effort required to compromise traffic (through interception and decryption) secured by a service using SSH v1 is significantly reduced, thus increasing the likelihood and risk of such an attack occurring.\n\nMore recent iterations of SSH services offer support for variations of SSH versions 1.5, 1.99 and 2.0 that can be controlled by configuration settings, so the tester has assumed that typical SSH connections are established using SSH v2 and that an attacker would have to manipulate a client attempting to establish a connection to the service in order to force a weaker SSH v1 connection to be established.\n\n"
	recommendation="Disable compatibility with version 1 of the protocol. References for implementing this change on Cisco devices and Linux hosts are available in the Notes Section."
	notes="<url>http://www.cisco-faq.com/178/disablesshv1sshversion2.html</url>\n<url>http://www.skullbox.net/disablessh1.php</url>"
	
	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
