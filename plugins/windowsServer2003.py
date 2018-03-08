from plugins import genFile

def gen(cb):
	appendices = []

	plugin_ids=['Microsoft Windows Server 2003 Unsupported Installation Detection','Microsoft Windows Server 2003 Unsupported Installation Detection (ERRATICGOPHER)']
	name='Microsoft Windows Server 2003 Installations'
	description="Hosts have been found to be running Microsoft Windows Server 2003. This operating system has now been retired by Microsoft and no longer receives security updates. The continued presence of such hosts leaves the affected assets and the network at risk of compromise through unaddressed issues."
	risk_description="Hosts were seen to be running Microsoft Windows Server 2003. Support for this operating system by Microsoft ended on July 14th, 2015. Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities. Furthermore, Microsoft is unlikely to investigate or acknowledge reports of vulnerabilities.\n\nWindows Server 2003 was affected by a number of attacks disclosed in the NSA Equation Group tool leak, including the exploit which was leveraged in the Petya and WannaCry malware attacks, reinforcing the risk its continued risk presents."
	recommendation="It is highly recommended that each instance of Windows Server 2003 be reviewed and replaced with a more recent, supported operating system."
	notes="<url>https://www.microsoft.com/en-gb/server-cloud/products/windows-server-2003/</url>"
	notes+="\n<url>http://windows.microsoft.com/en-gb/windows/end-support-help</url>"
	notes+="\n<url>http://support.microsoft.com/lifecycle/?p1=7274</url>"
	notes+="\n<url>https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/</url>"
	
	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices