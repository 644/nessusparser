from plugins import genParent

def gen(cb):
	plugin_ids=[35372]
	plugin_ids+=["DNS Server Cache Snooping Remote Information Disclosure"]

	description="DNS services provide a mechanism to map human-readable names to IP addresses. Issues associated with such services can facilitate a variety of attacks which can lead to the disclosure of sensitive information."

	genParent.genr(cb, plugin_ids, description)
