from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Linux Kernel TCP Sequence Number Generation Security Weakness']
	name="Linux Kernel TCP Sequence Number Generation"
	description="It may be possible to predict TCP/IP Initial Sequence Numbers for a host."
	risk_description="The Linux kernel is prone to a security weakness related to TCP sequence number generation. Attackers can exploit this issue to inject arbitrary packets into TCP sessions using a brute-force attack. An attacker may use this vulnerability to create a denial of service condition or invoke a man-in-the-middle attack."
	recommendation="Contact the OS vendor for a Linux kernel update / patch."
	notes="<url>https://github.com/torvalds/linux/commit/6e5714eaf77d79ae1c8b47e3e040ff5411b717ec</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices