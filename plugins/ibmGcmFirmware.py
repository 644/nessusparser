from plugins import genFile

def gen(cb):
	plugin_ids=['IBM GCM16 / GCM32 Global Console Manager KVM Switch Firmware Version%']
	name="IBM GCM KVM Switch Firmware"
	description="The web interface for IBM KVM switches is reported to be affected by multiple vulnerabilities."
	risk_description="Based on the reported version number returned by hosted web services, each affected host is an IBM Global Console Manager (GCM32) KVM switch using a dated firmware version (xxxxx). More recent versions have been made available to fix the following issues which could enable the compromise of the host. Mitigating factors, such as an authentication prerequisite for exploitation, have been noted.\n\n##########Issues###########"
	recommendation="Upgrade the firmware to the most recent version."
	notes=str()

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
