from plugins import genFile

def gen(cb):
	child_module = str()
	
	plugin_ids=['Unencrypted Telnet Server']
	name="Telnet Services"
	description="Hosts throughout the network were observed to be running a Telnet server service. Telnet is a historical remote terminal service used for configuring and managing devices remotely, but does it not typically enforce suitable security mechanisms to protect its data when in transit. As a result, Telnet traffic is usually sent in cleartext between a client and server, leaving it vulnerable to interception. As this traffic can include user credentials and system commands, its presence poses a considerable risk to each host it is deployed on."
	risk_description="Each of the hosts listed within the Affected Components section was seen to be running a Telnet service that transmits unencrypted (cleartext) traffic. An attacker who is able to successfully intercept this traffic, most likely by performing a Man-in-the-Middle (MitM) attack against a client or the server, will be able to read every exchange of data between the Telnet client and server. Depending on the function of each host, this could allow an attacker to intercept user credentials for remote access purposes, configuration alterations (which may include passwords) and sensitive information, such as firewall configurations.\n\nThe tester notes that whilst some Telnet deployments can support traffic encryption using SSL/TLS, these deployments were not seen to utilise this functionality."
	recommendation="Disable the Telnet service on each host and make use of a more secure alternative remote access solution, such as SSH.\n\nIf a host will not support SSH, force all Telnet communications to be encrypted using SSL/TLS.\n\nThe presence of any host that does not support SSH instead of Telnet should be reviewed, and if its presence is not a requirement, the host should be decommissioned. If the host must remain in place, filter access to these services from non-management assets."
	notes="<url>https://catn.com/2010/03/23/why-do-we-use-ssh-over-telnet/</url>"
	
	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes, child_module)
