from plugins import genFile

def gen(cb):
	plugin_ids = ['Microsoft Windows Unquoted Service Path Enumeration']
	remove_strings = ["Nessus found the following services with an untrusted path :","Nessus found the following service with an untrusted path :"]
	name = "Windows Unquoted Service Paths"
	description = "Authenticated assessment of Microsoft Windows hosts identified the presence of services configured on multiple hosts that use an unquoted service path. This configuration can assist in privilege escalation attacks, but leveraging the vulnerability requires authenticated access to the host."
	risk_description = "Several hosts have at least one service installed that uses an unquoted service path which contains at least one whitespace, for example <italic>C:\\My Service\\Service.exe</italic>. A local attacker can gain elevated privileges by inserting an executable file in the path of the affected service. In the example above, placing an executable at <italic>C:\\My.exe</italic> will cause this file to be executed when the service is restarted, with <italic>Service\\Service.exe</italic> being passed as arguments. As services typically run under accounts with high privileges, such as the SYSTEM account, this can lead to complete compromise of the affected host; however, exploiting this configuration requires initial authenticated access to the affected host.\n\nA list of affected services can be seen in the Notes section below."
	recommendation = "Ensure that any services that contain a space in the path are reconfigured to enclose the path in quotes."
	notes="<url>http://www.commonexploits.com/unquoted-service-paths/</url>\n<url>https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341</url>"
	
	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
