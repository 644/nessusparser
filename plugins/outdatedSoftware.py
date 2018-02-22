from plugins import genFile

def gen(cb):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Flash Player %', 'Adobe Flash Player %']
	name="Adobe Flash Player"
	description="Adobe Flash Player is used across a number of areas for presenting applications, streaming media or providing interactive activies (such as games or websites). Typically seen as a plugin or add-on for other applications (such as browsers), Adobe Flash Player is used to process Flash content (typically seen as embedded Shockwave Flash (SWF) files) and display it to the user. Historically, Adobe Flash Player has been affiliated with a number of issues that can lead to the execution of code on a host through the use of malicious Flash content. Such issues can result in allowing remote access to the targeted user's host."
	risk_description="By observing versions of the software installed, it was possible to identify at least one installation of the Adobe Flash Player software that is out of date and therefore vulnerable to a number of issues. The most severe of these vulnerabilities can result in the execution of arbitrary code on an affected host through the use of a file containing malicious Flash content (such as an embedded SWF file). This file would contain malicious code that, when loaded by Flash Player, would exploit flaws within the software (such as pointer handling or buffer overflows), resulting in the execution of code on the affected host."
	recommendation="It is highly recommended that all Adobe Flash Player deployments on the affected host be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://helpx.adobe.com/uk/security.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids ShockwavePlayer(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Variant","  File","  Installed version"]
	plugin_ids=['Shockwave Player %', 'Adobe Shockwave Player %']
	name="Shockwave Player"
	description="Adobe Shockwave Player is used for accessing Adobe Director generated interactive web content (including multimedia) within a web browser. The version of this software installed on the assessed hosts is outdated and therefore affected by multiple vulnerabilities that could lead to a host's compromise through malicious web content loaded by this plugin."
	risk_description="At least one host has been found to be running an outdated version of the Adobe Shockwave Player software. Code execution issues, including those leveraged through buffer overflows, are commonplace within such deployments of this plugin software and are addressed in more recent releases. By directing a user to a crafted Adobe Director file, an attacker would be able to compromise the host if it were used to access such content."
	recommendation="It is highly recommended that the Adobe Shockwave Player deployment on this host be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://helpx.adobe.com/uk/security.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids AdobeReader(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Adobe Reader %', 'Adobe Acrobat %']
	name="Adobe Reader"
	description="The Adobe Reader tool is used to view, amend and edit Portable Document File (PDF) formatted files. Such files are typically passed between users and businesses as a means of transferring data in an accessible format. Historically, Adobe Reader has been affiliated with a number of issues that have led to malicious PDF files being used as part of phishing or targeted user attacks to exploit vulnerable installations of Adobe Reader, typically allowing remote access to the targeted user's host."
	risk_description="At least one installation of the Adobe Reader software deployed on a host is out of date and vulnerable to a number of issues. The more severe of these vulnerabilities can result in the execution of arbitrary code on an affected host through the use of a malicious PDF. This file would contain injected malicious code that attacks flaws within the software, including its handling of pointers, buffer overflows or other issues, which would result in the code being executed on an attempt being made to view the file with the software. Successfully undertaken such activity is likely to grant an attacker remote access to a compromised host."
	recommendation="It is highly recommended that the Adobe Reader deployments on these assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://helpx.adobe.com/uk/security.html#reader</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Firefox(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version","    Path","    Installed version"]
	plugin_ids=['Firefox %','Mozilla Foundation Unsupported Application Detection', 'Mozilla Firefox %']
	name="Firefox"
	description="Mozilla Firefox is an open-source cross-platform web browser. At least one version of this software deployed on the hosts listed below is out of date and is therefore vulnerable to a number of security issues."		
	risk_description="Authenticated local vulnerability assessment has identified at least one deployment of an outdated version of Mozilla Firefox on the hosts listed below. The affected hosts are therefore vulnerable to numerous code execution issues due to the presence of buffer overflow and memory corruption vulnerabilities. Each of these issues has since been addressed in more recent software releases."
	recommendation="It is highly recommended that the Mozilla Firefox deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.mozilla.org/en-US/security/advisories/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids AdobeAir(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Adobe AIR %']
	name="Adobe AIR"
	description="Adobe AIR provides a cross-platform runtime environment for applications built using Adobe Flash, ActionScript and Flex. At least one version of this software deployed on the hosts listed below is out of date and is therefore vulnerable to a number of security issues."
	risk_description="Authenticated local vulnerability assessment has identified at least one deployment of an outdated version of Adobe AIR on the hosts listed below. The affected hosts are therefore vulnerable to numerous code execution issues due to the presence of buffer overflow and memory corruption vulnerabilities. Each of these issues, since addressed in more recent software releases, could be used to compromise a host by tricking a legitimate user into opening a crafted file (e.g. Flash, ActionScript, Flex)."
	recommendation="It is highly recommended that the Adobe AIR deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.adobe.com/support/programs/policies/supported.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Java(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Oracle Java %', 'Sun Java %']
	name="Oracle/Sun Java"
	description="Java Runtime Environments (JREs) and Development Kits (JDKs) provide a toolset for developing, debugging and running Java-based applications. At least one instance of outdated Oracle (previously Sun) distributions of this software has been identified on a host."
	risk_description="The version of at least one deployment of a Java JRE/JDK identified on a host is not in line with the most recent release for the relevant branch or is unsupported. Public support is currently only available for Oracle's Java 8 distributions; however, support for a number of branches prior to this is available through extended support contracts.\n\nOutdated versions are known to be affected by issues in various components, with each issue presenting its own level of risk. For runtime environments, exploiting such issues typically requires some degree of user interaction, such as a user running a malicious file using the runtime environment or by accessing a malicious resource using an existing Java application. The vulnerabilities known to affect these deployments include denial of service, information disclosure and code execution invoked through memory corruption, and stack and buffer overflows. Exploiting the more severe of these issues could lead to a compromise of the underlying host."
	recommendation="It is highly recommended that the Oracle Java JRE/JDK deployments on this host be brought in line with the most recent stable software release for the relevant branch. In cases where extended support is required but not available, upgrade the JRE/JDK deployments to a publicly supported release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases.\n\nThe presence of dated software versions is often attributed to specific client applications only supporting a specific JRE version. If the application is provided by a third party, a long-term support and migration solution should be sought to enable such Java installations to be updated."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.oracle.com/technetwork/java/eol-135779.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids CitrixReceiverICA(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Citrix ICA Client%', 'Citrix XenApp Online Plug-in %','Citrix Receiver / Online Plug-in Remote Code Execution (CTX134681)']	
	name="Citrix Receiver/ICA Client/XenApp Online Plug-in"
	description=str()
	risk_description="Installations of the Citrix Online Plug-in/ICA Client/Receiver installed on several hosts are running on outdated versions. Several issues are known to affect older releases of this software, including a man-in-the-middle vulnerability for which details remain unspecificed. This issue is reported to relate to Microsoft security bulletin MS09-056, and is likely due to a failure to detect null bytes in the common name of a server certificate. A remote attacker could exploit this to perform a man-in-the-middle attack which would allow them to read or modify SSL/TLS traffic being sent to/from these systems."
	recommendation="Upgrade the Citrix Online Plug-in/ICA Client software to a supported release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.citrix.com/search?searchQuery=%3F&lang=en&sort=cr_date_desc&ct=Security+Bulletin&prod=Citrix%20Receiver</url>"
	notes+="\n<url>https://support.citrix.com/search?searchQuery=%3F&lang=en&sort=cr_date_desc&ct=Security+Bulletin&prod=XenApp%20Plug-ins%20(Clients)</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids GoogleChrome(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Google Chrome %']	
	name="Google Chrome"
	description="Chrome is a cross-platform web browser developed by Google. At least one version of this software deployed on the hosts listed below is out of date and is therefore vulnerable to a number of security issues."
	risk_description="Authenticated local vulnerability assessment has identified at least one deployment of an outdated version of Google Chrome on the hosts listed below. The affected hosts are therefore vulnerable to numerous code execution issues due to the presence of buffer overflow and memory corruption vulnerabilities. Each of these issues has since been addressed in more recent software releases."
	recommendation="It is highly recommended that the Google Chrome deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://googlechromereleases.blogspot.co.uk/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Wireshark(ManyToOnePlugin):
	plugin_ids=['Wireshark %']	
	name="Wireshark"
	description="Wireshark is an open source cross-platform netork packet and protocol analyser used to capture and analyse raw network traffic. At least one version of this software deployed on the hosts listed below is out of date and is therefore vulnerable to a number of security issues."
	risk_description="Authenticated local vulnerability assessment has identified at least one deployment of an outdated version of Wireshark on the hosts listed below. The affected hosts are therefore vulnerable to numerous code execution issues due to the presence of buffer overflow and memory corruption vulnerabilities. Each of these issues has since been addressed in more recent software releases."
	recommendation="It is highly recommended that the Wireshark deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids VLC(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]	
	plugin_ids=['VLC %']	
	name="VLC Player"
	description="VLC Media Player is an open-source media player capable of handling various multimedia formats, including audio and video, as well as providing functionality for reading physical media, such as CDs and DVDs, and presenting streaming services. An outdated installation of this software presents a risk to the host it was identified on."
	risk_description="Authenticated assessment of the affected hosts has identified that the installed version of the VLC Media Player software and its plugins are out of date, with more recent versions having been released to address known vulnerabilities. As a result, these installations are susceptible to exploitation through malicious content presented to the software in a form which it will attempt to open/present to the user. Exploitation of a number of these issues results in code execution on the host, providing a mechanism for host compromise, provided a user can be manipulated into accessing a malicious resource/file."
	recommendation="It is highly recommended that the VLC Media Player deployments on all assets be brought in line with the most recent stable software release.\n\nIt is also possible to limit the impact this software installation may have by removing the vulnerable plugins from the host. A list of these is provided in the Notes section.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.videolan.org/vlc/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids VSphere(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['VMware vSphere Client %']
	name="VMware vSphere Client"
	description="VMware vSphere Client is used for the remote administration of VMware ESX hypervisors and the vCenter management software. Outdated instances of this software have been found on hosts within the network."
	risk_description="By running authenticated local vulnerability assessments and observing versions of the software installed on each host, it was possible to identify installations of the VMware vSphere Client software deployed on the affected hosts that are out of date and therefore vulnerable to a number of issues."
	recommendation="It is highly recommended that the VMware vSphere Client deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.vmware.com/uk/security/advisories.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids CiscoVPN(ManyToOnePlugin):
	plugin_ids=['Cisco VPN Client cvpnd.exe Privilege Escalation','Cisco VPN Client Unsupported']	
	name="Cisco VPN Client"
	description="Cisco VPN client is used to provide clients with access to remote networks via Virtual Private Network (VPN) tunnels. The version of this software installed on networked hosts has been found to be outdated and therfore vulnerable to a number of issues."
	risk_description="The Cisco VPN clients installed on the affected hosts have a privilege escalation vulnerability. cvpnd.exe, which is executed by the Cisco VPN Service, has insecure permissions; a local attacker could replace this file with arbitrary code, which would later be executed by the Cisco VPN Service, resulting in an elevation of privileges."
	recommendation="It is highly recommended that the Cisco VPN Client deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"	

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Silverlight(ManyToOnePlugin):
	plugin_ids=['Microsoft Silverlight Unsupported Version Detection (Windows)']	
	name="Microsoft Silverlight"
	description=str()
	risk_description="According to its version, the installation of Microsoft Silverlight on the Windows host is no longer supported. Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities."
	recommendation="It is highly recommended that the Silverlight deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.microsoft.com/en-gb/lifecycle/search?alpha=silverlight</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids HPVCA(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['HP Version Control Agent (VCA) < %']	
	name="HP Version Control Agent"
	description=str()
	risk_description="According to their versions, the installations of HP Version Control Agent on the affected hosts are out of date and known to contain multiple vulnerabilities."
	recommendation="It is highly recommended that the HP Version Control Agent deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.hpe.com/hpsc/swd/public/detail?swItemId=MTX_c9e525cfc0d646338da25bd87c</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids HPVCR(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['HP Version Control Repository Manager%']	
	name="HP Version Control Repository Manager"
	description=str()
	risk_description="According to their versions, the installations of HP Version Control Repository Manager on the affected hosts are out of date and known to contain multiple vulnerabilities."
	recommendation="It is highly recommended that the HP Version Control Repository deployments on all assets be brought in line with the most recent stable software release.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids FileZilla(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['FileZilla Client %']	
	name="FileZilla Client"
	description=str()
	risk_description="The installation of FileZilla Client on the remote systems have been found to be outdated. The installed versions of the software are known to be vulnerable to multiple issues, including remote code execution, which could be exploited if the client were used to connect to a malicious server."
	recommendation="It is recommended that the FileZilla Client deployments on all assets be updated to the most recent stable available version.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://filezilla-project.org/versions.php</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids InternetExplorer(StringExtractionPlugin,ManyToOnePlugin):
	plugin_ids=['Microsoft Internet Explorer Unsupported Version Detection']	
	name="Microsoft Internet Explorer"
	description=str()
	risk_description="The installations of Microsoft Internet Explorer on the affected systems have been found to be outdated and are no longer supported by Microsoft. Lack of support implies that no further software updates will be made available, and current and future security vulnerabilities will not be addressed. "
	recommendation="It is recommended that Internet Explorer be updated to the most recent stable version available for each deployed operating system.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."	
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.microsoft.com/en-gb/WindowsForBusiness/End-of-IE-support</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids MicrosoftOffice(StringExtractionPlugin,ManyToOnePlugin):
	plugin_ids=['Microsoft Office Service Pack Out of Date','Microsoft Office Unsupported Version Detection']	
	name="Microsoft Office"
	description=str()
	risk_description="The installations of Microsoft Office on the affected systems have been found to be outdated and are no longer supported by Microsoft. Lack of support implies that no further software updates will be made available, and current and future security vulnerabilities will not be addressed. "
	recommendation="It is recommended that Microsoft Office be updated to the most recent stable version and Service Pack available.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.microsoft.com/en-us/lifecycle/search?alpha=Microsoft%20Office</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids dotNETFramework(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Installed version"]
	plugin_ids=['Microsoft .NET Framework Unsupported','Microsoft .NET Framework Service Pack Out of Date']	
	name="Microsoft .NET Framework"
	description=str()
	risk_description="The installations of the Microsoft .NET Framework on the affected systems have been found to be outdated and are no longer supported by Microsoft. Lack of support implies that no further software updates will be made available, and current and future security vulnerabilities will not be addressed. "
	recommendation="It is recommended that the .NET Framework be updated to the most recent stable version available. Currently, versions 3.5, 4.5.2, 4.6 and 4.6.1 are supported by Microsoft.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.microsoft.com/en-gb/gp/framework_faq/en-us</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids SQLServer(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Installed version"]
	plugin_ids=['Microsoft SQL Server Unsupported Version Detection']
	name="Microsoft SQL Server"
	description=str()
	risk_description="The installations of Microsoft SQL Server on the affected systems have been found to be outdated and are no longer supported by Microsoft. Lack of support implies that no further software updates will be made available, and current and future security vulnerabilities will not be addressed. "
	recommendation="It is recommended that the SQL Server instances be updated to the most recent stable version available or removed from each host if no longer required.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids MicrosoftVisio(ManyToOnePlugin):
	plugin_ids=['Microsoft Visio Unsupported Version Detection']	
	name="Microsoft Visio"
	description=str()
	risk_description="The installations of Microsoft Visio present on affected systems have been found to be outdated and are no longer supported by Microsoft. Lack of support implies that no further software updates will be made available, and current and future security vulnerabilities will not be addressed. "
	recommendation="It is recommended that these Visio deployments be removed if no longer required or be updated to the most recent stable version available.\n\nRegular reviews of this software should be undertaken to ensure that each deployment remains up to date with recent releases."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids AdobeDigitalEditions(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Adobe Digital Editions%']	
	name="Adobe Digital Additions"
	description=str()
	risk_description="The affected host has been found to have a version of Adobe Digital Editions software installed that is known to be affected by multiple security vulnerabilities. This may allow an attacker to overwrite arbitrary files on the host system or potentially execute code via buffer overflow."
	recommendation="It is recommended that the Adobe Digital Editions software be upgraded to the most recent stable release available."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids WinZIP(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]	
	plugin_ids=['WinZIP Unsupported']	
	name="WinZip"
	description=str()
	risk_description="The affected hosts have been found to have unsupported versions of WinZIP installed. Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities."
	recommendation="It is recommended that WinZIP be upgraded to the most recent supported release available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.winzip.com/winzip/version.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Seven7Zip(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['7-Zip Unsupported','7-Zip < 16%']	
	name="7-Zip"
	description=str()
	risk_description="The affected hosts have been found to have unsupported versions of 7-Zip installed. Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities."
	recommendation="It is recommended that 7-Zip be upgraded to the most recent supported release available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.7-zip.org/history.txt</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids WinSCP(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]	
	plugin_ids=['WinSCP %']	
	name="WinSCP"
	description=str()
	risk_description="Installations of the WinSCP file transfer client are outdated and affected by known vulnerabilities. More recent releases have been made available which address issues including those associated with bundled versions of OpenSSL libraries (e.g. denial of service and information disclosure, such as the Heartbleed bug) and buffer overflow issues."
	recommendation="Remove the WinSCP client from assets on which it is not required. Upgrade it to the most recent, stable release where required."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://winscp.net/eng/docs/history</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Putty(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['PuTTY %']	
	name="PuTTY"
	description=str()
	risk_description="Installations of the PuTTY remote access client are outdated and affected by known vulnerabilities. More recent releases have been made available which address issues including those associated with such versions, including information disclosure (e.g. user passwords) and overflow vulnerabilities."
	recommendation="Remove the PuTTY client from assets on which it is not required. Upgrade it to the most recent, stable release where required."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids IBMNotes(ManyToOnePlugin):
	plugin_ids=['IBM Notes %','Lotus Notes %','IBM Lotus Notes %']	
	name="IBM/Lotus Notes"
	description=str()
	risk_description="Installations of the IBM/Lotus Notes software found on assessed hosts were seen to be outdated (i.e. missing fix pack updates) and susceptible to several issues, including those associated with bundled versions of the Java Runtime Environment (JRE), information disclosure and unauthorised file write access. Such issues threaten the security of the underlying hosts as well as any data they handle."
	recommendation="Upgrade each Notes installation to the most recent, stable release where it is required. Otherwise, remove the software."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids IBMDB2(ManyToOnePlugin):
	plugin_ids=['IBM DB2 9.7 %']	
	name="IBM DB2 9.7"
	description=str()
	risk_description="Installations of the IBM DB2 Database Server software found on assessed hosts were seen to be running outdated (i.e. missing fix pack updates) versions and as a result are susceptible to several issues, including information disclosure and denial-of-service attacks. In these deployments, leveraging these vulnerabilities requires authenticated access to the DB2 instances which offers a degree of risk mitigation."
	recommendation="Upgrade each DB2 9.7 installation to the most recent, stable supported release."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids IBMTivoliStorageClient(ManyToOnePlugin):
	plugin_ids=['IBM Tivoli Storage Manager Client %','IBM Spectrum Protect Client%']
	name="IBM Tivoli Storage Manager/Spectrum Protect Client"
	description=str()
	risk_description="Installations of the IBM Tivoli Storage Manager Client (now Spectrum Protect Client) were identified on assessed hosts that are running outdated versions and as a result are susceptible to several issues. These issues may include information disclosure, denial-of-service and code execution attacks (depending on the exact version installed) which require either local access to the underlying host/software or for an attacker to trick a user to connect to/open a malicious resource, limiting the likelihood of leveraging this issue."
	recommendation="Upgrade the software to the most recent release. Tivoli Storage Manager Client deployments will need to be upgraded to Spectrum Protect Client."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids IBMLotusDomino(ManyToOnePlugin):
	plugin_ids=['IBM Domino %']	
	name="IBM Domino"
	description=str()
	risk_description="Installations of the IBM Domino software found on assessed hosts were seen to be running outdated (i.e. missing fix pack updates) versions and as a result are susceptible to several issues, including those associated with bundled Java Runtime Environments, common TLS/SSL vulnerabilites (leaving traffic susceptible to inteception and decryption), security bypasses, information disclosure and denial-of-service attacks."
	recommendation="Upgrade each Domino installation to the most recent, stable supported release for its branch. If the branch is no longer supported, identify a suitable upgrade path to a supported release."
	notes="\n<bold>"+name+"</bold>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids HPInsight(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['HP Systems Insight Manager < %']	
	name="HP Systems Insight Manager"
	description=str()
	risk_description="Installations of the HP Systems Insight Manager software found on hosts during the assessment were seen to be running outdated versions and as a result are susceptible to several issues, including those associated with bundled Flash components, common web application attack vectors (e.g. cross-site scripting, clickjacking) and security bypasses."
	recommendation="Upgrade each HP Systems Insight Manager installation to the most recent, stable supported release. Alternatively remove the software if it is no longer required."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www8.hp.com/uk/en/products/server-software/product-detail.html?oid=489496</url>"
	notes+="\n<url>http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04271436</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids OpenVPN(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['OpenVPN %']	
	name="OpenVPN"
	description=str()
	risk_description="At least one installation of a dated version of the OpenVPN software was identified on hosts exposed to authenticated assessment. As a result, such deployments are susceptible to various issues, including those which can enable denial-of-service attacks, impacting the availability of the underlying host/service."
	recommendation="Remove the OpenVPN deployment if not required or upgrade it to the most recent release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://community.openvpn.net/openvpn/wiki/ChangesInOpenvpn23</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Firebird(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Firebird SQL Server %']	
	name="Firebird SQL Server"
	description=str()
	risk_description="The version of the Firebird SQL server software installed on hosts exposed to authenticated assessment is outdated and therefore susceptible to various issues, including those which can enable denial-of-service attacks, impacting the availability of the underlying host/service."
	recommendation="Remove the Firebird deployment if not required or upgrade it to the most recent release.\n\nIf provided as part of a wider third party software deployment, discuss potential upgrade paths with the relevant vendor."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://firebirdsql.org/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids VCenterOrchestrator(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Installed version"]
	plugin_ids=['VMware vCenter / vRealize Orchestrator %']	
	name="VMware vCenter/vRealize Orchestrator"
	description=str()
	risk_description="The version of the VMware vCenter/vRealize Orchestrator software installed on assessed hosts is susceptible to several issues which have been addressed in more recent releases. Some of the known vulnerabilities affecting this software include those which can allow for code execution on the underlying host as a result of the software utilising third-party libraries with known weaknesses (e.g. Apache Commons-Collections)."
	recommendation="Remove the software if not required or upgrade it to the most recent release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.vmware.com/security/advisories/VMSA-2015-0009.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids GoogleSketchup(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Google SketchUp %']	
	name="Google SketchUp"
	description=str()
	risk_description="The SketchUp 3-D modeling application was seen to be installed on a number of hosts. The versions present are outdated and affected by known vulnerabilities. Specially crafted files can be used to leverage buffer overflow vulnerabilities which will result in an application crash or the execution of arbitrary code. A host could be exploited if a user is tricked into opening such a file."
	recommendation="Remove the SketchUp installation if it is not required, otherwise update each deployment in line with the most recent release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://www.sketchup.com/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Photoshop(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Adobe Photoshop %','Photoshop %']	
	name="Adobe Photoshop"
	description=str()
	risk_description="Installations of the Adobe Photoshop image editing software present on hosts is outdated. These versions are affected by known vulnerabilities which can be leveraged using specially crafted files (e.g. image files, such as GIF, TIFF etc.). Several buffer overflow vulnerabilities, which can result in an application crash or the execution of arbitrary code if leveraged, can be exploited if a user is tricked into opening a crafted file. Any code executed in this manner will be subject to the privileges of the user running the application."
	recommendation="Remove the Photoshop installation if it is not required, otherwise update each deployment in line with the most recent release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://helpx.adobe.com/uk/security.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids FlashProfessional(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Adobe Flash Professional%']	
	name="Adobe Flash Professional"
	description=str()
	risk_description="Installations of older versions of the Adobe Flash Professional software were found on hosts during authenticated assessment. Such versions are affected by known vulnerabilities which can be leveraged using specially crafted files (e.g. image files, such as JPG, TIFF etc). Overflow vulnerabilities (i.e. integer/buffer etc) are included within such issues, which can result in an application crash or the execution of arbitrary code if exploited by tricking a user into opening a crafted file. Any code executed in this manner will be subject to the privileges of the user running the application."
	recommendation="Upgrade the Adobe Flash Professional software to the most recent, supported release for its branch or remove it from affected hosts."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://helpx.adobe.com/uk/security.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Illustrator(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Adobe Illustrator %']	
	name="Adobe Illustrator"
	description=str()
	risk_description="Installations of older versions of the Adobe Illustrator software were found on hosts during authenticated assessment. Such versions are affected by known vulnerabilities which can be leveraged using specially crafted files. Issues known to affect this software permits the loading of DLL files from a user's current working directory. Launching the application from within a directory which contains a malicious DLL named the same as a legitimate DLL called by the application would result in code execution on the host. Other issues also include various memory corrupton vulnerabilities which can result in arbitrary code execution on the underlying host."
	recommendation="Upgrade the Adobe Illustrator software to the most recent, supported release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://helpx.adobe.com/uk/security.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Quicktime(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Apple Quicktime %','Quicktime %']	
	name="Apple Quicktime"
	description=str()
	risk_description="The Apple Quicktime software installed on hosts is no longer supported on Windows platforms. Without support no further security updates will be made available for this software, leaving each deployment presenting a persistent threat. Vulnerabilities affecting such deployments include buffer overflows and other memory corruption issues, each of which can result in an application crash or the execution of arbitrary code. Exploiting such issues requires a user to be tricked into opening maliciously crafted files with the application, with any code executed in this manner being subject to the privileges of that user."
	recommendation="Remove each Quicktime installation as it is no longer supported."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.apple.com/en-us/HT205771</url>"
	notes+="\n<url>https://www.us-cert.gov/ncas/alerts/TA16-105A</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids VMwarePlayer(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['VMware Player %']
	name="VMware Player"
	description=str()
	risk_description="The version of the VMware Player desktop virtualisation application installed on hosts is outdated and therefore susceptible to vulnerabilities addressed in more recent releases. Issues know to affect such version include privilege escalation within guest operating systems and issues affecting bundled versions of the OpenSSL libraries."
	recommendation="Remove VMware Player if not required or update deployments to the latest release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.vmware.com/uk/security/advisories.html</url>"
	notes+="\n<url>http://www.vmware.com/products/player.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids CameraRaw(StringExtractionPlugin,ManyToOnePlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Adobe Camera Raw %']
	name="Adobe Camera Raw Plug-in"
	description=str()
	risk_description="Installations of the Adobe Camera Raw Plug-in present on hosts are using versions that are affected by overflow vulnerabilities. Such vulnerabilities can be invoked using crafted image files (e.g. TIFF) to execute arbitrary code on the underlying host. Tricking a user into opening such a file with the application would result in code executing with the privileges of that user."
	recommendation="Remove the Camera Raw Plug-in if not required, otherwise update it in line with the most recent, supported release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://helpx.adobe.com/uk/security.html</url>"
	notes+="\n<url>https://helpx.adobe.com/photoshop/topics/camera-raw.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids AppleSoftwareUpdate(StringExtractionPlugin,VulnerabilityPlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Apple Software Update Insecure Transport']	
	name="Apple Software Update"
	description=str()
	risk_description="The version of Apple Software Update installed on the affected hosts does not use the HTTPS protocol when transferring the updates window contents. By modifying the data stream between the client and server an attacker can therefore control the contents of the updates window."
	recommendation="It is recommended that Apple Software Update is updated to its most recent available release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.apple.com/en-us/HT206091</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids LibreOffice(StringExtractionPlugin,VulnerabilityPlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['LibreOffice < %']	
	name="LibreOffice"
	description=str()
	risk_description="The affected hosts have been found to have outdated versions of LibreOffice installed. These versions contain known security vulnerabilities within the libraries used to process input files that could allow an attacker to execute arbitrary code if a malicious file were to be opened."
	recommendation="It is recommended that the LibreOffice suite is updated to its most recent available release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.libreoffice.org/about-us/security/advisories</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids ApacheOpenOffice(StringExtractionPlugin,VulnerabilityPlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Apache OpenOffice <%']	
	name="Apache OpenOffice"
	description=str()
	risk_description="The affected hosts have been found to have outdated versions of Apache OpenOffice installed. These versions contain known security vulnerabilities within the libraries used to process input files that could allow an attacker to execute arbitrary code if a malicious file were to be opened."
	recommendation="It is recommended that the Apache OpenOffice suite is updated to its most recent available release."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.openoffice.org/security/bulletin.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids iTunes(StringExtractionPlugin,VulnerabilityPlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Apple iTunes < %']	
	name="Apple iTunes"
	description=str()
	risk_description="The affected hosts have been found to have a outdated versions of Apple iTunes installed. Older versions of iTunes contain known security vulnerabilities within the bundled web browsing engine, as well as within the application itself."
	recommendation="It is recommended that iTunes be upgraded to the most recent supported release available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://support.apple.com/en-gb/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids AutoDeskAutoCAD(StringExtractionPlugin,VulnerabilityPlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Autodesk AutoCAD%']	
	name="Autodesk AutoCAD"
	description=str()
	risk_description="The affected hosts have been found to have outdated versions of Autodesk AutoCAD installed. Older versions of AutoCAD contain known security vulnerabilities."
	recommendation="It is recommended that AutoCAD be upgraded to the most recent supported release available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://knowledge.autodesk.com/support/autocad/downloads</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids AutoDeskDesignReview(StringExtractionPlugin,VulnerabilityPlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['Autodesk Design Review <%']	
	name="Autodesk Design Review"
	description=str()
	risk_description="The affected hosts have been found to have outdated versions of Autodesk Design Review installed. Older versions of Design Review contain known security vulnerabilities."
	recommendation="It is recommended that Design Review be upgraded to the most recent supported release available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://knowledge.autodesk.com/support/design-review?cg=Downloads</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids Cygwin(VulnerabilityPlugin):
	plugin_ids=['Cygwin <%']	
	name="Cygwin"
	description=str()
	risk_description="Cygwin, a Linux-like environment for Windows, is installed on at least one host and is running a version affected by a known issue. Vulnerabilities associated with Cygwin have been previously known to allow local users to execute arbitrary code on the host with the privileges of the Cygwin installation which could provide a path to privilege escalation on the host as well as remote compromise."
	recommendation="It is recommended that Cygwin be upgraded to the most recent supported release available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>http://cygwin.com/ml/cygwin-developers/2007-11/msg00001.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)

	# New plugin_ids VMwareHorizonView(StringExtractionPlugin, VulnerabilityPlugin):
	include_strings=["  Path","  Installed version"]
	plugin_ids=['VMware Horizon View Client%(VMSA-%','VMware Horizon View Client <%']
	name="VMware Horizon View Client"
	description=str()
	risk_description="The VMware Horizon View Client virtual desktop solution is installed on at least one host and is running an outdated version affected by at least one known vulnerability. Issues reported against older VMware Horizon View releases have affected both the software itself and the bundled version of the OpenSSL library it uses to secure its traffic."
	recommendation="It is recommended that the VMware Horizon View Client software be upgraded to the most recent supported release available."
	notes="\n<bold>"+name+"</bold>"
	notes+="\n<url>https://www.vmware.com/uk/security/advisories.html</url>"
	
	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
