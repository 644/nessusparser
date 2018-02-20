from plugins import genFile

def gen(cb):
	plugin_ids=['Microsoft Windows Update Reboot Required']
	name="Microsoft Windows Update Reboot Required"
	description="At least one host has been identified which requires a reboot in order to apply recently installed updates. As such updates commonly include security fixes, leaving a host in this state leaves it persistently vulnerable to issues which have already been remedied."
	risk_description="Authenticated assessment of hosts has identified that a number require a reboot in order to apply outstanding updates. Without rebooting each host will be unable to apply these updates, including any security fixes, leaving each host vulnerable to issues which have otherwise been addressed."
	recommendation="Force a manual reboot of each affected host when possible to ensure that any pending updates are suitably applied."
	notes="<url>https://technet.microsoft.com/library/cc960241.aspx</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
