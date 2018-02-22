from plugins import genFile

def gen(cb):
	description=str()
	notes=str()

	plugin_ids=["%Rename administrator account%"]
	name="Group Policy: Rename administrator account"
	risk_description="The local Administrator account (RID 500) remains named as \"Administrator\". The local Administrator account is not subject to account lockout policies enforced through password policies and can form a suitable target for brute-force attacks. Compromising the local Administrator account on a domain-integrated host can also have onward impact to the domain security. In cases where this account has been suitably disabled, the risk this finding presents is reduced."
	recommendation="Rename the local \"Administrator\" (RID 500) account to a different, uncommon value."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids RenameGuestAccount(CompliancePlugin):
	plugin_ids=["%Rename guest account%"]
	name="Group Policy: Rename guest account"
	risk_description="The built-in local guest account remains named as \"guest\" which is a known, common configuration. It is recommended to rename this account to something that does not indicate its purpose, even if this account is disabled. In cases where this account has been suitably disabled, the risk this finding presents is reduced."
	recommendation="Rename the local \"Guest\" account to a different, uncommon value."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids DoNotAllowAnonymousEnumerationOfSAMAccountsAndShares(CompliancePlugin):
	plugin_ids=["%Do not allow anonymous enumeration of SAM accounts and shares%"]
	name="Group Policy: Do not allow anonymous enumeration of SAM accounts and shares"
	risk_description="The current setting of this control allows an anonymous users to enumerate shares and accounts within the System Accounts Manager (SAM) on the hosts. This can allow an attacker to recover information about possible target user accounts."
	recommendation="Enable the following policy:\n\n<italic>Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network access:Do not allow anonymous enumeration of SAM accounts and shares</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids AdminApprovalModeForBuiltinAdministrator(CompliancePlugin):
	plugin_ids=["%Admin Approval Mode for the Built-in Administrator account%"]
	name="Group Policy: Run all administrators in Admin Approval Mode"
	risk_description="This control defines whether an elevation prompt is displayed to the built-in Administrator account on a host. In its current setting, executing any action as the local Administrator will not require an additional approval check on either host. It is recommended that this setting be enabled to require all administrative actions undertaken as the local Administrator invoke a prompt for consent."
	recommendation="To implement the recommended configuration state, set the following Group Policy setting to \"enabled\":\n\n<italic>Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control- Admin Approval Mode for the Built-in Administrator account</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids BehaviorOfTheElevationPromptForAdministratorsInAdminApprovalMode(CompliancePlugin):
	plugin_ids=["%Behavior of the Elevation Prompt for Administrators in Admin Approval Mode%"]
	name="Group Policy: Behavior of the Elevation Prompt for Administrators in Admin Approval Mode"
	risk_description="This control defines how the elevation prompt is displayed to administrative users. In its current setting, an elevation prompt is only presented to administrator attempting to run non-Windows binaries with administrative rights, leaving both the hosts/users susceptible to limited drive by attacks in which an application is executed with elevated permissions without the the user requiring to permit it. It is recommended that this setting require all actions which require administrative permissions prompt the user for their credentials to enable the action to run with such privileges."
	recommendation="Ideally, set this policy \"Prompt for Credentials on the secure desktop\":\n\n<italic>Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids ApplyUACRestrictionsToLocalAccountsOnNetworkLogons(CompliancePlugin):
	plugin_ids=["%Apply UAC restrictions to local accounts on network logons%"]
	name="Group Policy: Apply UAC restrictions to local accounts on network logons"
	risk_description="This setting controls whether local accounts on hosts can be used for remote administration via network logon (e.g. via NET USE, C$ share etc.). Local accounts are at high risk for credential theft, especially if the same account and password is configured on multiple systems. This policy is currently disabled, leaving hosts permitting their remote management using locally configured accounts."
	recommendation="An additional Group Policy template (PtH.admx/adml) is required to enforce the recommended setting for this value via Group Policy and is included with Microsoft Security Compliance Manager (SCM).\n\nTo establish the recommended configuration via group policy once this is installed, set the following UI path to Enabled:\n\n<italic>Computer Configuration\\Policies\\Administrative Templates\\SCM: Pass the Hash Mitigations\\Apply UAC restrictions to local accounts on network logons</italic>\n\nAlternatively, the following registry key could be removed or set to \"0\":\n\n<italic>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids DoNotDisplayLastUserName(CompliancePlugin):
	plugin_ids=["%Do not display last user name%"]
	name="Group Policy: Do not display last user name"
	risk_description="The current disabled state of this setting permits the host to remember and present the username of the last user who logged into it to any subsequent login attempts (e.g. over RDP). This reveals valid usernames to potential attackers who can connect to this service, leaving them prone to targeted brute-force attacks."
	recommendation="Enable the following policy:\n\n<italic>Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Do not display last user name</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids NumberOfPreviousLogonsToCache(CompliancePlugin):
	plugin_ids=["%Number of previous logons to cache%"]
	name="Group Policy: Number of previous logons to cache"
	risk_description="The current configuration allows the local caching of user passwords for up to 10 users when they log in and is meant to provide a solution to login failures if there is an issue with the existing domain controller hosts. If the host is compromised, an attacker would be able to recover legitimate user credentials that may have domain privileges. This could facilitate the compromise of other domain-connected hosts. As this host is integrated to the domain, this configuration is seen to be unnecessary unless there are concerns regarding Domain Controller availability or the device used is mobile (e.g. a laptop)."
	recommendation="Set the following policy to a smaller value (ideally 0):\n\n<italic>Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Number of previous logons to cache (in case domain controller is not available)</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids RequireDomainControllerAuthenticationToUnlockWorkstation(CompliancePlugin):
	plugin_ids=["%Require Domain Controller authentication to unlock workstation%"]
	name="Group Policy: Require Domain Controller authentication to unlock workstation"
	risk_description="This policy setting dictates that hosts are able to authenticate users without requiring a domain controller be accessible. Non-mobile assets, such as server and desktop hosts, are expected to have persistent connectivity to a domain controller, with the exception of an instance of a significant network failure. The presence of this setting compliments the \"Number of previous logons to cache\" finding, in which recent user logons are cached by the hosts to permit authentication when a domain controller is not available. The tester sees this configuration as being in excess of requirements for non-mobile assets but may be required to provide suitable functionality for mobile devices, such as laptops."
	recommendation="Unless this setting is required to provide redundancy for mobile devices, enable the following policy setting:\n\n<italic>Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Interactive logon: Require Domain Controller authentication to unlock workstation</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MinimumSessionSecurityForNTLMSSPBasedServers(CompliancePlugin):
	plugin_ids=["%Minimum session security for NTLM SSP based % servers%"]
	name="Group Policy: Minimum session security for NTLM SSP based servers"
	risk_description="This policy setting determines which behaviours are allowed for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services, with the value set for these policies dictating the security controls required to establish secure connections. Currently this policy is set to only \"Require 128-bit encryption\", foregoing the additional security afforded by NTLMv2 session security."
	recommendation="Set the following policy to \"require NTLMv2 session security, require 128-bit encryption\":\n\n<italic>Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network Security: Minimum session security for NTLM SSP based (including secure RPC) servers</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MinimumSessionSecurityForNTLMSSPBasedClients(CompliancePlugin):
	plugin_ids=["%Minimum session security for NTLM SSP based % clients%"]
	name="Group Policy: Minimum session security for NTLM SSP based clients"
	risk_description="This policy setting determines which behaviours are allowed for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services, with the value set for these policies dictating the security controls required to establish secure connections. Currently this policy is set to only \"Require 128-bit encryption\", foregoing the additional security afforded by NTLMv2 session security."
	recommendation="Set the following policy to \"require NTLMv2 session security, require 128-bit encryption\":\n\n<italic>Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options\\Network Security: Minimum session security for NTLM SSP based (including secure RPC) clients</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids LAPSAdmPwdGPOExtension(CompliancePlugin):
	plugin_ids=["%LAPS AdmPwd GPO Extension / CSE%"]
	name="LAPS AdmPWD GPO Extension"
	risk_description="The Local Administrator Password Solution (LAPS) tool functionality was not installed on the assessed host. LAPS provides an Active Directory Schema update alongside a Group Policy Client Side Extension (CSE) which enables the configuration of randomised and unique local administrator account password on domain connected hosts. These values are stored within Active Directory and can be recovered by administrative users\n\n#CLIENT# may have an alternative solution in place for managing such settings, and the size of the environment greatly limits the number of local administrator passwords which need to be configured."
	recommendation="Review the potential benefits and feasibility of implementing LAPS (unless an existing process/solution is in place). If desired, install LAPS and the relevant Group Policy templates and enable the following Group Policy once it is installed:\n\n<italic>Computer Configuration\\Policies\\Administrative Templates\\LAPS\\Enable Local Admin Password Management</italic>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids HardenedUNCPaths(CompliancePlugin): ###not complete, plugin_id is likely wrong.
	plugin_ids=["%Hardened UNC Paths%"]
	name="Hardened UNC Paths"
	risk_description="The configuration of a risk mitigation Group Policy setting was not observed. This can be in the form of a missing update (KB3000483) or missing the additional configuration of a Group Policy administrative template needed to enable these mitigations. As a result such hosts are not implementing mitigations for known remote code execution attack vectors."
	#recommendation="If missing from a host, install the KB3000483 update.\n\nConfigure the \"NetworkProvider.admx/adml\" administrative template (part of the KB3000483 update). The recommended settings for this template are:\n\n<italic>\\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1</italic>\n<italic>\\\\\\\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1</italic>\n\nIt should be noted that enforcing additional checks/controls on this functionality can hinder connectivity to services from older operating systems or those which utilise functionality which do not support these additional features. Enabling such changes may affect services within the environment and should be reviewed thoroughly before actioning such a change."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
