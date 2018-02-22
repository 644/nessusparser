from plugins import genParent

def gen(cb):
	plugin_ids=[97861]
	plugin_ids+=[43156]
	plugin_ids+=[71783]
	plugin_ids+=["Network Time Protocol Daemon (ntpd) %<%"]
	
	description="NTP Service Issues\nA number of hosts have been found with Network Time Protocol (NTP) server services listening. Each service is affected by at least one known issue introduced by a service misconfiguration or due to the service running on top of an older software version. These issues are typically limited to potential denial-of-service or information disclosure attacks."

	genParent.genr(cb, plugin_ids, description)
