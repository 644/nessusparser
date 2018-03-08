from plugins import genParent

def gen(cb):
	appendices = []

	plugin_ids=[51894,51895]
	plugin_ids+=[26014]
	plugin_ids+=["Macrovision FLEXnet %","FLEXNet %"]
	plugin_ids+=["Data Dynamics %"]
	plugin_ids+=["EasyMail SMTP Object ActiveX Control Multiple Buffer Overflows"]
	plugin_ids+=['Oracle Document Capture Multiple Vulnerabilities']	
	plugin_ids+=['Adobe SVG Viewer Circle Transform Remote Code Execution']	
	plugin_ids+=['Evernote < 5.8.1 ActiveX Control Arbitrary File Overwrite']
	plugin_ids+=['Autodesk Design Review AdView.AdViewer ActiveX Control RCE']	
	plugin_ids+=['Autodesk IDrop ActiveX Control Heap Corruption']

	description="ActiveX Controls\nHosts have been identified with vulnerable ActiveX controls installed. Hosts would be at risk of remote compromise if a user was tricked into accessing malicious resources.\n<url>https://support.microsoft.com/kb/240797</url>\n\n"

	genParent.genr(cb, plugin_ids, description)
