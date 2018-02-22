from plugins import genFile

def gen(cb):
	description=str()

	plugin_ids=[51894,51895]
	name="SigPlus Pro ActiveX Control"
	risk_description="The SigPlus Pro ActiveX control, used for electronic signature integration with Topaz signature pads and installed on Windows hosts, is using a dated version. Such versions are reported to be affected by a number of vulnerabilities, including a number of stack and heap overflow issues. Leveraging such issues, e.g. by directing a user/browser to a malicious resources, could lead to the remote compromise of the underlying host."
	recommendation="Upgrade to the most recent, supported SigPlus Pro ActiveX version or remove the control."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-0323</url>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-0324</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	## New plugins
	plugin_ids=[26014]
	name="ER Mapper NCSView"
	risk_description="The 'NCSView' ActiveX control, distributed as part of the ER Mapper package and used to view maps in Internet Explorer, is installed on a host. The version of this control contains multiple stack-based buffer overflows. If an attacker can trick a user on the affected host into visiting a specially crafted web page, this issue could be leveraged to execute arbitrary code on the host subject to the user's privileges."
	recommendation="Either disable the use of this ActiveX control from within Internet Explorer by setting its kill bit or upgrade to ER Mapper version 8.1 (version 3.4.0.242 of the NCSView control itself) or later."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2007-4470</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	plugin_ids=["Macrovision FLEXnet %","FLEXNet %"]
	name="Macrovision FLEXnet"
	risk_description="Macrovision FLEXnet Connect, formerly known as InstallShield Update Service, is installed on a host. This software management solution for internally-developed and third-party applications may have been installed as part of the FLEXnet Connect SDK, other InstallShield software, or by running FLEXnet Connect-enabled Windows software.\n\FLEXnet Connect client includes ActiveX controls, including the InstallShield Update Service Agent and DWUpdateService. Issues affecting such controls have been reported to include being marked as 'safe for scripting', containing several methods that allow for downloading and launching arbitrary programs, buffer overflow issues and reportedly allowing a remote, unauthenticated attacker to execute arbitrary commands. If a remote attacker can trick a user on the affected host into visiting a specially crafted web page, this issue could be leveraged to execute arbitrary code on the host subject to the user's privileges."
	recommendation="Either disable the use of these ActiveX controls or upgrade the FLEXnet Connect software on the hosts."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://flexeracommunity.force.com/customer/articles/en_US/INFO/Q113602</url>"
	notes+="\n<url>http://support.installshield.com/kb/view.asp?articleid=Q113020</url>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2007-0328</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	plugin_ids=["Data Dynamics %"]
	name="Data Dynamics ActiveBar"
	risk_description="Windows hosts have an at least one Data Dynamics ActiveBar ActiveX control installed. This control is reportedly affected by a code execution vulnerability due to unspecified issues in the 'Save()', 'SaveLayoutChanges()', 'SaveMenuUsageData()', and 'SetLayoutData()' methods. If a remote attacker can trick a user on the affected host into visiting a specially crafted web page, this issue could be leveraged to execute arbitrary code on the host subject to the user's privileges."
	recommendation="Remove or disable the controls as fixes are not available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2011-0323</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	plugin_ids=["EasyMail SMTP Object ActiveX Control Multiple Buffer Overflows"]
	include_strings = ["  Filename","  Installed version"]
	name="EasyMail"
	risk_description="At least one Windows host has an installation of the EasyMail Objects, a set of COM objects for supporting email protocols. These objects commonly come bundled with a third-party application, such as Oracle Document Capture, Earthlink internet access software, Borland Caliber RM Client and FrontRange Heat.\n\nThe SMTP component of the version of this control installed on the host is reported to be affected by multiple buffer overflows involving the AddAttachment and SubmitToExpress methods that could lead to arbitrary code execution on the affected system.\n\nSuccessful exploitation requires that an attacker trick a user on the affected host into visiting a specially crafted web page."
	recommendation="Either disable its use from within Internet Explorer by setting its kill bit or remove it completely."
	notes="<bold>"+name+"</bold>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2007-4607</url>"
	notes+="\n<url>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-4663</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	include_strings=["  Filename","  Installed version"]	
	plugin_ids=['Oracle Document Capture Multiple Vulnerabilities']	
	name="Oracle Document Capture"
	description=str()
	risk_description="A version of the Oracle Document Capture ActiveX control that is known to be affected by multiple security vulnerabilities has been found on the affected hosts. This may allow an attacker to overwrite arbitrary files on the host systems or potentially execute code via buffer overflow."
	recommendation="It is recommended that Oracle's Document Capture client be updated to the most recent available version so that the ActiveX controls are disabled. If this software has been bundled alongside another application that includes the NCSEcw.dll control, it is recommended that the ActiveX kill bit be set for the affected control."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	include_strings=["  Path","  Version"]
	plugin_ids=['Adobe SVG Viewer Circle Transform Remote Code Execution']	
	name="Adobe SVG Viewer"
	description=str()
	risk_description="A version of the Adobe SVG Viewer ActiveX control, known to be affected by a remote code execution vulnerability, has been found on the affected hosts. Leveraging this issue by directing a user to a malicious web page can allow the execution of code on the underlying host, potentially leading to its compromise. This control is also no longer supported by Adobe, increasing the risk it is seen to present as this issue will not be addressed."
	recommendation="As the SVG Viewer is no longer supported, it should be removed."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.adobe.com/devnet/svg/adobe-svg-viewer-eol.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	include_strings=["  Filename","  Version"]
	plugin_ids=['Evernote < 5.8.1 ActiveX Control Arbitrary File Overwrite']	
	name="Evernote"
	description=str()
	risk_description="Deployments of the Evernote ActiveX control were identified on hosts as a result of authenticated assessment. The versions seen predate releases which addressed security issues, including a vulnerability which allowed a remote, unauthenticated attacker to read and overwrite arbitrary files on the affected hosts. Leveraging such issues requires a user to browse to a malicious web page, reducing the likelihood of exploitation of this control."
	recommendation="Remove the control if it is not required, otherwise update it in line with the most recent release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://discussion.evernote.com/topic/79359-evernote-for-windows-581/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	include_strings=["  Filename","  Installed version"]
	plugin_ids=['Autodesk Design Review AdView.AdViewer ActiveX Control RCE']	
	name="Autodesk Design Review AdView"
	description=str()
	risk_description="Deployments of the AutoDesk Design Review AdView ActiveX control were identified on hosts as a result of authenticated assessment. The versions seen predate releases which addressed security issues, including a vulnerability which allowed a remote, unauthenticated attacker to execute arbitrary code on the affected hosts. Leveraging such issues requires a user to open a malicious file (e.g. email attachment) or browse to a malicious web page, reducing the likelihood of exploitation of this control."
	recommendation="Remove the control if it is not required, otherwise update it in line with the most recent release. Vendor advice for this issue requires all deployments be upgraded to the 2013 release and then a 2013 hotfix be applied to them."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://nvd.nist.gov/vuln/detail/CVE-2014-9268</url>"
	notes+="\n<url>https://knowledge.autodesk.com/support/design-review/downloads/caas/downloads/content/autodesk-design-review-2013-hotfix.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	## New plugins
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Autodesk IDrop ActiveX Control Heap Corruption']	
	name="AutoDesk IDrop"
	description=str()
	risk_description="Deployments of the AutoDesk IDrop ActiveX control were identified on hosts as a result of authenticated assessment. The versions seen predate releases which addressed security issues, including a vulnerability which allows an attacker to execute arbitrary code on the affected hosts. Public exploit code is available for this vulnerability. Leveraging such issues requires a user to open a malicious HTML file, requiring additional exploitation of the user (e.g. through social engineering) in order to leverage this attack. This is seen to reduce the likelihood of exploitation of this control.\n\nIt should also be noted that AutoDesk no longer support this control, resulting in its presence introducing a persistent risk to the underlying hosts."
	recommendation="Remove this control if it is not required. As it is no longer supported continued use of this control is not recommended."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.rapid7.com/db/modules/exploit/windows/browser/autodesk_idrop</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
