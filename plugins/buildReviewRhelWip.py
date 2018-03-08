from plugins import genFile

def gen(cb):
	appendices = []

	notes=str()
	description=str()

	plugin_ids=["%Ensure no duplicate group names exist%"]
	name="Ensure no duplicate group names exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenoduplicateusernamesexist(CompliancePlugin):
	plugin_ids=["%Ensure no duplicate user names exist%"]
	name="Ensure no duplicate user names exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurenoduplicateGIDsexist(CompliancePlugin):
	plugin_ids=["%Ensure no duplicate GIDs exist%"]
	name="Ensure no duplicate GIDs exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurenoduplicateUIDsexist(CompliancePlugin):
	plugin_ids=["%Ensure no duplicate UIDs exist%"]
	name="Ensure no duplicate UIDs exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureallgroupsinetcpasswdexistinetcgroup(CompliancePlugin):
	plugin_ids=["%Ensure all groups in /etc/passwd exist in /etc/group%"]
	name="Ensure all groups in /etc/passwd exist in /etc/group"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenousershaverhostsfiles(CompliancePlugin):
	plugin_ids=["%Ensure no users have .rhosts files%"]
	name="Ensure no users have .rhosts files"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureusersnetrcFilesarenotgrouporworldaccessible(CompliancePlugin):
	plugin_ids=["%Ensure users .netrc Files are not group or world accessible%"]
	name="Ensure users .netrc Files are not group or world accessible"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenousershavenetrcfiles(CompliancePlugin):
	plugin_ids=["%Ensure no users have .netrc files%"]
	name="Ensure no users have .netrc files"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenousershaveforwardfiles(CompliancePlugin):
	plugin_ids=["%Ensure no users have .forward files%"]
	name="Ensure no users have .forward files"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureusersdotfilesarenotgrouporworldwritable(CompliancePlugin):
	plugin_ids=["%Ensure users dot files are not group or world writable%"]
	name="Ensure users dot files are not group or world writable"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureusersowntheirhomedirectories(CompliancePlugin):
	plugin_ids=["%Ensure users own their home directories%"]
	name="Ensure users own their home directories"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureusershomedirectoriespermissionsare750ormorerestrictive(CompliancePlugin):
	plugin_ids=["%Ensure users home directories permissions are 750 or more restrictive%"]
	name="Ensure users home directories permissions are 750 or more restrictive"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureallusershomedirectoriesexist(CompliancePlugin):
	plugin_ids=["%Ensure all users home directories exist%"]
	name="Ensure all users home directories exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurerootPATHIntegrity(CompliancePlugin):
	plugin_ids=["%Ensure root PATH Integrity%"]
	name="Ensure root PATH Integrity"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurerootistheonlyUID0account(CompliancePlugin):
	plugin_ids=["%Ensure root is the only UID 0 account%"]
	name="Ensure root is the only UID 0 account"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenolegacyentriesexistinetcgroup(CompliancePlugin):
	plugin_ids=["%Ensure no legacy + entries exist in /etc/group%"]
	name="Ensure no legacy + entries exist in /etc/group"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenolegacyentriesexistinetcshadow(CompliancePlugin):
	plugin_ids=["%Ensure no legacy + entries exist in /etc/shadow%"]
	name="Ensure no legacy + entries exist in /etc/shadow"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenolegacyentriesexistinetcpasswd(CompliancePlugin):
	plugin_ids=["%Ensure no legacy + entries exist in /etc/passwd%"]
	name="Ensure no legacy + entries exist in /etc/passwd"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordfieldsarenotempty(CompliancePlugin):
	plugin_ids=["%Ensure password fields are not empty%"]
	name="Ensure password fields are not empty"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids AuditSGIDexecutables(CompliancePlugin):
	plugin_ids=["%Audit SGID executables%"]
	name="Audit SGID executables"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids AuditSUIDexecutables(CompliancePlugin):
	plugin_ids=["%Audit SUID executables%"]
	name="Audit SUID executables"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenoungroupedfilesordirectoriesexist(CompliancePlugin):
	plugin_ids=["%Ensure no ungrouped files or directories exist%"]
	name="Ensure no ungrouped files or directories exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenounownedfilesordirectoriesexist(CompliancePlugin):
	plugin_ids=["%Ensure no unowned files or directories exist%"]
	name="Ensure no unowned files or directories exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenoworldwritablefilesexist(CompliancePlugin):
	plugin_ids=["%Ensure no world writable files exist%"]
	name="Ensure no world writable files exist"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcgshadowareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/gshadow- are configured%"]
	name="Ensure permissions on /etc/gshadow- are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcgroupareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/group- are configured%"]
	name="Ensure permissions on /etc/group- are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcshadowareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/shadow- are configured%"]
	name="Ensure permissions on /etc/shadow- are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcpasswdareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/passwd- are configured%"]
	name="Ensure permissions on /etc/passwd- are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcgshadowareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/gshadow are configured%"]
	name="Ensure permissions on /etc/gshadow are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcgroupareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/group are configured%"]
	name="Ensure permissions on /etc/group are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcshadowareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/shadow are configured%"]
	name="Ensure permissions on /etc/shadow are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcpasswdareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/passwd are configured%"]
	name="Ensure permissions on /etc/passwd are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureaccesstothesucommandisrestrictedwheelgroupcontainsroot(CompliancePlugin):
	plugin_ids=["%Ensure access to the su command is restricted - wheel group contains root%"]
	name="Ensure access to the su command is restricted - wheel group contains root"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureaccesstothesucommandisrestrictedpam_wheelso(CompliancePlugin):
	plugin_ids=["%Ensure access to the su command is restricted - pam_wheel.so%"]
	name="Ensure access to the su command is restricted - pam_wheel.so"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurerootloginisrestrictedtosystemconsole(CompliancePlugin):
	plugin_ids=["%Ensure root login is restricted to system console%"]
	name="Ensure root login is restricted to system console"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuredefaultuserumaskis027ormorerestrictiveetcprofile(CompliancePlugin):
	plugin_ids=["%Ensure default user umask is 027 or more restrictive - /etc/profile%"]
	name="Ensure default user umask is 027 or more restrictive - /etc/profile"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuredefaultuserumaskis027ormorerestrictiveetcbashrc(CompliancePlugin):
	plugin_ids=["%Ensure default user umask is 027 or more restrictive - /etc/bashrc%"]
	name="Ensure default user umask is 027 or more restrictive - /etc/bashrc"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsuredefaultgroupfortherootaccountisGID0(CompliancePlugin):
	plugin_ids=["%Ensure default group for the root account is GID 0%"]
	name="Ensure default group for the root account is GID 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuresystemaccountsarenonlogin(CompliancePlugin):
	plugin_ids=["%Ensure system accounts are non-login%"]
	name="Ensure system accounts are non-login"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureinactivepasswordlockis30daysorless(CompliancePlugin):
	plugin_ids=["%Ensure inactive password lock is 30 days or less%"]
	name="Ensure inactive password lock is 30 days or less"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordexpirationwarningdaysis7ormore(CompliancePlugin):
	plugin_ids=["%Ensure password expiration warning days is 7 or more%"]
	name="Ensure password expiration warning days is 7 or more"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureminimumdaysbetweenpasswordchangesis7ormore(CompliancePlugin):
	plugin_ids=["%Ensure minimum days between password changes is 7 or more%"]
	name="Ensure minimum days between password changes is 7 or more"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordexpirationis90daysorless(CompliancePlugin):
	plugin_ids=["%Ensure password expiration is 90 days or less%"]
	name="Ensure password expiration is 90 days or less"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurepasswordhashingalgorithmisSHA512passwordauth(CompliancePlugin):
	plugin_ids=["%Ensure password hashing algorithm is SHA-512 - password-auth%"]
	name="Ensure password hashing algorithm is SHA-512 - password-auth"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurepasswordhashingalgorithmisSHA512systemauth(CompliancePlugin):
	plugin_ids=["%Ensure password hashing algorithm is SHA-512 - system-auth%"]
	name="Ensure password hashing algorithm is SHA-512 - system-auth"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordreuseislimitedpasswordauth(CompliancePlugin):
	plugin_ids=["%Ensure password reuse is limited - password-auth%"]
	name="Ensure password reuse is limited - password-auth"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordreuseislimitedsystemauth(CompliancePlugin):
	plugin_ids=["%Ensure password reuse is limited - system-auth%"]
	name="Ensure password reuse is limited - system-auth"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptspasswordauthauthsufficientpamfaillocksoauthsuccauditdeny5unlocktime900(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - password-auth auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900%"]
	name="Lockout for failed password attempts - password-auth auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptspasswordauthauthdefaultdiepamfaillocksoauthfailauditdeny5unlocktime900(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - password-auth auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900%"]
	name="Lockout for failed password attempts - password-auth auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptspasswordauthauthsuccess1defaultbadpamunixso(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - password-auth auth [success=1 default=bad] pam_unix.so%"]
	name="Lockout for failed password attempts - password-auth auth [success=1 default=bad] pam_unix.so"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptspasswordauthauthrequiredpamfaillocksopreauthauditsilentdeny5unlocktime900(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - password-auth auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900%"]
	name="Lockout for failed password attempts - password-auth auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptssystemauthauthsufficientpamfaillocksoauthsuccauditdeny5unlocktime900(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - system-auth auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900%"]
	name="Lockout for failed password attempts - system-auth auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptssystemauthauthdefaultdiepamfaillocksoauthfailauditdeny5unlocktime900(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - system-auth auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900%"]
	name="Lockout for failed password attempts - system-auth auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptssystemauthauthsuccess1defaultbadpamunixso(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - system-auth auth [success=1 default=bad] pam_unix.so%"]
	name="Lockout for failed password attempts - system-auth auth [success=1 default=bad] pam_unix.so"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Lockoutforfailedpasswordattemptssystemauthauthrequiredpamfaillocksopreauthauditsilentdeny5unlocktime900(CompliancePlugin):
	plugin_ids=["%Lockout for failed password attempts - system-auth auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900%"]
	name="Lockout for failed password attempts - system-auth auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfiguredlcredit(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - lcredit%"]
	name="Ensure password creation requirements are configured - lcredit"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfiguredocredit(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - ocredit%"]
	name="Ensure password creation requirements are configured - ocredit"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfigureducredit(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - ucredit%"]
	name="Ensure password creation requirements are configured - ucredit"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfigureddcredit(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - dcredit%"]
	name="Ensure password creation requirements are configured - dcredit"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfiguredminlen(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - minlen%"]
	name="Ensure password creation requirements are configured - minlen"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfiguredsystemauthretry3(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - system-auth retry=3%"]
	name="Ensure password creation requirements are configured - system-auth retry=3"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfiguredpasswordauthretry3(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - password-auth retry=3%"]
	name="Ensure password creation requirements are configured - password-auth retry=3"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfiguredsystemauthtryfirstpass(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - system-auth try_first_pass%"]
	name="Ensure password creation requirements are configured - system-auth try_first_pass"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepasswordcreationrequirementsareconfiguredpasswordauthtryfirstpass(CompliancePlugin):
	plugin_ids=["%Ensure password creation requirements are configured - password-auth try_first_pass%"]
	name="Ensure password creation requirements are configured - password-auth try_first_pass"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHwarningbannerisconfigured(CompliancePlugin):
	plugin_ids=["%Ensure SSH warning banner is configured%"]
	name="Ensure SSH warning banner is configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHaccessislimited(CompliancePlugin):
	plugin_ids=["%Ensure SSH access is limited%"]
	name="Ensure SSH access is limited"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHLoginGraceTimeissettooneminuteorless(CompliancePlugin):
	plugin_ids=["%Ensure SSH LoginGraceTime is set to one minute or less%"]
	name="Ensure SSH LoginGraceTime is set to one minute or less"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHIdleTimeoutIntervalisconfiguredClientAliveCountMax(CompliancePlugin):
	plugin_ids=["%Ensure SSH Idle Timeout Interval is configured - ClientAliveCountMax%"]
	name="Ensure SSH Idle Timeout Interval is configured - ClientAliveCountMax"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHIdleTimeoutIntervalisconfiguredClientAliveInterval(CompliancePlugin):
	plugin_ids=["%Ensure SSH Idle Timeout Interval is configured - ClientAliveInterval%"]
	name="Ensure SSH Idle Timeout Interval is configured - ClientAliveInterval"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureonlyapprovedMACalgorithmsareused(CompliancePlugin):
	plugin_ids=["%Ensure only approved MAC algorithms are used%"]
	name="Ensure only approved MAC algorithms are used"
	risk_description=str()
	recommendation="Edit the /etc/ssh/sshd_config file to set the parameter in accordance with organisation/environment policy. The following includes all supported and accepted MACs:\n\nMACS hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureonlyapprovedciphersareused(CompliancePlugin):
	plugin_ids=["%Ensure only approved ciphers are used%"]
	name="Ensure only approved ciphers are used"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHPermitUserEnvironmentisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure SSH PermitUserEnvironment is disabled%"]
	name="Ensure SSH PermitUserEnvironment is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHPermitEmptyPasswordsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure SSH PermitEmptyPasswords is disabled%"]
	name="Ensure SSH PermitEmptyPasswords is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHrootloginisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure SSH root login is disabled%"]
	name="Ensure SSH root login is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHHostbasedAuthenticationisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure SSH HostbasedAuthentication is disabled%"]
	name="Ensure SSH HostbasedAuthentication is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHIgnoreRhostsisenabled(CompliancePlugin):
	plugin_ids=["%Ensure SSH IgnoreRhosts is enabled%"]
	name="Ensure SSH IgnoreRhosts is enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHMaxAuthTriesissetto4orless(CompliancePlugin):
	plugin_ids=["%Ensure SSH MaxAuthTries is set to 4 or less%"]
	name="Ensure SSH MaxAuthTries is set to 4 or less"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHX11forwardingisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure SSH X11 forwarding is disabled%"]
	name="Ensure SSH X11 forwarding is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHLogLevelissettoINFO(CompliancePlugin):
	plugin_ids=["%Ensure SSH LogLevel is set to INFO%"]
	name="Ensure SSH LogLevel is set to INFO"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSSHProtocolissetto2(CompliancePlugin):
	plugin_ids=["%Ensure SSH Protocol is set to 2%"]
	name="Ensure SSH Protocol is set to 2"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcsshsshd_configareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/ssh/sshd_config are configured%"]
	name="Ensure permissions on /etc/ssh/sshd_config are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureatcronisrestrictedtoauthorizedusersatdeny(CompliancePlugin):
	plugin_ids=["%Ensure at/cron is restricted to authorized users - at.deny%"]
	name="Ensure at/cron is restricted to authorized users - at.deny"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureatcronisrestrictedtoauthorizedusersatallow(CompliancePlugin):
	plugin_ids=["%Ensure at/cron is restricted to authorized users - at.allow%"]
	name="Ensure at/cron is restricted to authorized users - at.allow"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureatcronisrestrictedtoauthorizeduserscrondeny(CompliancePlugin):
	plugin_ids=["%Ensure at/cron is restricted to authorized users - cron.deny%"]
	name="Ensure at/cron is restricted to authorized users - cron.deny"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureatcronisrestrictedtoauthorizeduserscronallow(CompliancePlugin):
	plugin_ids=["%Ensure at/cron is restricted to authorized users - cron.allow%"]
	name="Ensure at/cron is restricted to authorized users - cron.allow"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetccrondareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/cron.d are configured%"]
	name="Ensure permissions on /etc/cron.d are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetccronmonthlyareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/cron.monthly are configured%"]
	name="Ensure permissions on /etc/cron.monthly are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetccronweeklyareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/cron.weekly are configured%"]
	name="Ensure permissions on /etc/cron.weekly are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetccrondailyareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/cron.daily are configured%"]
	name="Ensure permissions on /etc/cron.daily are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetccronhourlyareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/cron.hourly are configured%"]
	name="Ensure permissions on /etc/cron.hourly are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetccrontabareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/crontab are configured%"]
	name="Ensure permissions on /etc/crontab are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurecrondaemonisenabled(CompliancePlugin):
	plugin_ids=["%Ensure cron daemon is enabled%"]
	name="Ensure cron daemon is enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurelogrotateisconfigured(CompliancePlugin):
	plugin_ids=["%Ensure logrotate is configured%"]
	name="Ensure logrotate is configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonalllogfilesareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on all logfiles are configured%"]
	name="Ensure permissions on all logfiles are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurersyslogorsyslogngisinstalled(CompliancePlugin):
	plugin_ids=["%Ensure rsyslog or syslog-ng is installed%"]
	name="Ensure rsyslog or syslog-ng is installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureremotersyslogmessagesareonlyacceptedondesignatedloghostsInputTCPServerRun514(CompliancePlugin):
	plugin_ids=["%Ensure remote rsyslog messages are only accepted on designated log hosts. - InputTCPServerRun 514%"]
	name="Ensure remote rsyslog messages are only accepted on designated log hosts. - InputTCPServerRun 514"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureremotersyslogmessagesareonlyacceptedondesignatedloghostsimtcpso(CompliancePlugin):
	plugin_ids=["%Ensure remote rsyslog messages are only accepted on designated log hosts. - imtcp.so%"]
	name="Ensure remote rsyslog messages are only accepted on designated log hosts. - imtcp.so"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurersyslogisconfiguredtosendlogstoaremoteloghost(CompliancePlugin):
	plugin_ids=["%Ensure rsyslog is configured to send logs to a remote log host%"]
	name="Ensure rsyslog is configured to send logs to a remote log host"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurersyslogdefaultfilepermissionsconfigured(CompliancePlugin):
	plugin_ids=["%Ensure rsyslog default file permissions configured%"]
	name="Ensure rsyslog default file permissions configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureloggingisconfigured(CompliancePlugin):
	plugin_ids=["%Ensure logging is configured%"]
	name="Ensure logging is configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurersyslogServiceisenabled(CompliancePlugin):
	plugin_ids=["%Ensure rsyslog Service is enabled%"]
	name="Ensure rsyslog Service is enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurewirelessinterfacesaredisabled(CompliancePlugin):
	plugin_ids=["%Ensure wireless interfaces are disabled%"]
	name="Ensure wireless interfaces are disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurefirewallrulesexistforallopenports(CompliancePlugin):
	plugin_ids=["%Ensure firewall rules exist for all open ports%"]
	name="Ensure firewall rules exist for all open ports"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureoutboundandestablishedconnectionsareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure outbound and established connections are configured%"]
	name="Ensure outbound and established connections are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureloopbacktrafficisconfigured(CompliancePlugin):
	plugin_ids=["%Ensure loopback traffic is configured%"]
	name="Ensure loopback traffic is configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsuredefaultdenyfirewallpolicyChainOUTPUT(CompliancePlugin):
	plugin_ids=["%Ensure default deny firewall policy - Chain OUTPUT%"]
	name="Ensure default deny firewall policy - Chain OUTPUT"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsuredefaultdenyfirewallpolicyChainFORWARD(CompliancePlugin):
	plugin_ids=["%Ensure default deny firewall policy - Chain FORWARD%"]
	name="Ensure default deny firewall policy - Chain FORWARD"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsuredefaultdenyfirewallpolicyChainINPUT(CompliancePlugin):
	plugin_ids=["%Ensure default deny firewall policy - Chain INPUT%"]
	name="Ensure default deny firewall policy - Chain INPUT"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureiptablesisinstalled(CompliancePlugin):
	plugin_ids=["%Ensure iptables is installed%"]
	name="Ensure iptables is installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureTIPCisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure TIPC is disabled%"]
	name="Ensure TIPC is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureRDSisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure RDS is disabled%"]
	name="Ensure RDS is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSCTPisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure SCTP is disabled%"]
	name="Ensure SCTP is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureDCCPisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure DCCP is disabled%"]
	name="Ensure DCCP is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetchostsdenyare644(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/hosts.deny are 644%"]
	name="Ensure permissions on /etc/hosts.deny are 644"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetchostsallowareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/hosts.allow are configured%"]
	name="Ensure permissions on /etc/hosts.allow are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureetchostsdenyisconfigured(CompliancePlugin):
	plugin_ids=["%Ensure /etc/hosts.deny is configured%"]
	name="Ensure /etc/hosts.deny is configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureetchostsallowisconfigured(CompliancePlugin):
	plugin_ids=["%Ensure /etc/hosts.allow is configured%"]
	name="Ensure /etc/hosts.allow is configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureTCPWrappersisinstalled(CompliancePlugin):
	plugin_ids=["%Ensure TCP Wrappers is installed%"]
	name="Ensure TCP Wrappers is installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureIPv6isdisabled(CompliancePlugin):
	plugin_ids=["%Ensure IPv6 is disabled%"]
	name="Ensure IPv6 is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureIPv6redirectsarenotacceptednetipv6confallacceptredirects0(CompliancePlugin):
	plugin_ids=["%Ensure IPv6 redirects are not accepted - net.ipv6.conf.all.accept_redirects = 0%"]
	name="Ensure IPv6 redirects are not accepted - net.ipv6.conf.all.accept_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureIPv6redirectsarenotacceptednetipv6confdefaultacceptredirects0(CompliancePlugin):
	plugin_ids=["%Ensure IPv6 redirects are not accepted - net.ipv6.conf.default.accept_redirects = 0%"]
	name="Ensure IPv6 redirects are not accepted - net.ipv6.conf.default.accept_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureIPv6routeradvertisementsarenotacceptednetipv6confdefaultaccept_ra0(CompliancePlugin):
	plugin_ids=["%Ensure IPv6 router advertisements are not accepted - net.ipv6.conf.default.accept_ra = 0%"]
	name="Ensure IPv6 router advertisements are not accepted - net.ipv6.conf.default.accept_ra = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureIPv6routeradvertisementsarenotacceptednetipv6confallaccept_ra0(CompliancePlugin):
	plugin_ids=["%Ensure IPv6 router advertisements are not accepted - net.ipv6.conf.all.accept_ra = 0%"]
	name="Ensure IPv6 router advertisements are not accepted - net.ipv6.conf.all.accept_ra = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureTCPSYNCookiesisenabled(CompliancePlugin):
	plugin_ids=["%Ensure TCP SYN Cookies is enabled%"]
	name="Ensure TCP SYN Cookies is enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureReversePathFilteringisenablednetipv4confallrp_filter1(CompliancePlugin):
	plugin_ids=["%Ensure Reverse Path Filtering is enabled - net.ipv4.conf.all.rp_filter = 1%"]
	name="Ensure Reverse Path Filtering is enabled - net.ipv4.conf.all.rp_filter = 1"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureReversePathFilteringisenablednetipv4confdefaultrp_filter1(CompliancePlugin):
	plugin_ids=["%Ensure Reverse Path Filtering is enabled - net.ipv4.conf.default.rp_filter = 1%"]
	name="Ensure Reverse Path Filtering is enabled - net.ipv4.conf.default.rp_filter = 1"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurebogusICMPresponsesareignored(CompliancePlugin):
	plugin_ids=["%Ensure bogus ICMP responses are ignored%"]
	name="Ensure bogus ICMP responses are ignored"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurebroadcastICMPrequestsareignored(CompliancePlugin):
	plugin_ids=["%Ensure broadcast ICMP requests are ignored%"]
	name="Ensure broadcast ICMP requests are ignored"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuresuspiciouspacketsareloggednetipv4confdefaultlog_martians1(CompliancePlugin):
	plugin_ids=["%Ensure suspicious packets are logged - net.ipv4.conf.default.log_martians = 1%"]
	name="Ensure suspicious packets are logged - net.ipv4.conf.default.log_martians = 1"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuresuspiciouspacketsareloggednetipv4confalllog_martians1(CompliancePlugin):
	plugin_ids=["%Ensure suspicious packets are logged - net.ipv4.conf.all.log_martians = 1%"]
	name="Ensure suspicious packets are logged - net.ipv4.conf.all.log_martians = 1"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsuresecureICMPredirectsarenotacceptednetipv4confallsecureredirects0(CompliancePlugin):
	plugin_ids=["%Ensure secure ICMP redirects are not accepted - net.ipv4.conf.all.secure_redirects = 0%"]
	name="Ensure secure ICMP redirects are not accepted - net.ipv4.conf.all.secure_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsuresecureICMPredirectsarenotacceptednetipv4confdefaultsecureredirects0(CompliancePlugin):
	plugin_ids=["%Ensure secure ICMP redirects are not accepted - net.ipv4.conf.default.secure_redirects = 0%"]
	name="Ensure secure ICMP redirects are not accepted - net.ipv4.conf.default.secure_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureICMPredirectsarenotacceptednetipv4confdefaultacceptredirects0(CompliancePlugin):
	plugin_ids=["%Ensure ICMP redirects are not accepted - net.ipv4.conf.default.accept_redirects = 0%"]
	name="Ensure ICMP redirects are not accepted - net.ipv4.conf.default.accept_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureICMPredirectsarenotacceptednetipv4confallacceptredirects0(CompliancePlugin):
	plugin_ids=["%Ensure ICMP redirects are not accepted - net.ipv4.conf.all.accept_redirects = 0%"]
	name="Ensure ICMP redirects are not accepted - net.ipv4.conf.all.accept_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuresourceroutedpacketsarenotacceptednetipv4confallaccept_source_route0(CompliancePlugin):
	plugin_ids=["%Ensure source routed packets are not accepted - net.ipv4.conf.all.accept_source_route = 0%"]
	name="Ensure source routed packets are not accepted - net.ipv4.conf.all.accept_source_route = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuresourceroutedpacketsarenotacceptednetipv4confdefaultaccept_source_route0(CompliancePlugin):
	plugin_ids=["%Ensure source routed packets are not accepted - net.ipv4.conf.default.accept_source_route = 0%"]
	name="Ensure source routed packets are not accepted - net.ipv4.conf.default.accept_source_route = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepacketredirectsendingisdisablednetipv4confdefaultsendredirects0(CompliancePlugin):
	plugin_ids=["%Ensure packet redirect sending is disabled - net.ipv4.conf.default.send_redirects = 0%"]
	name="Ensure packet redirect sending is disabled - net.ipv4.conf.default.send_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepacketredirectsendingisdisablednetipv4confallsendredirects0(CompliancePlugin):
	plugin_ids=["%Ensure packet redirect sending is disabled - net.ipv4.conf.all.send_redirects = 0%"]
	name="Ensure packet redirect sending is disabled - net.ipv4.conf.all.send_redirects = 0"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureLDAPclientisnotinstalled(CompliancePlugin):
	plugin_ids=["%Ensure LDAP client is not installed%"]
	name="Ensure LDAP client is not installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretelnetclientisnotinstalled(CompliancePlugin):
	plugin_ids=["%Ensure telnet client is not installed%"]
	name="Ensure telnet client is not installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretalkclientisnotinstalled(CompliancePlugin):
	plugin_ids=["%Ensure talk client is not installed%"]
	name="Ensure talk client is not installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurershclientisnotinstalled(CompliancePlugin):
	plugin_ids=["%Ensure rsh client is not installed%"]
	name="Ensure rsh client is not installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureNISClientisnotinstalled(CompliancePlugin):
	plugin_ids=["%Ensure NIS Client is not installed%"]
	name="Ensure NIS Client is not installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurersyncserviceisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure rsync service is not enabled%"]
	name="Ensure rsync service is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretftpserverisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure tftp server is not enabled%"]
	name="Ensure tftp server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretelnetserverisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure telnet server is not enabled%"]
	name="Ensure telnet server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretalkserverisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure talk server is not enabled%"]
	name="Ensure talk server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurershserverisnotenabledrsh(CompliancePlugin):
	plugin_ids=["%Ensure rsh server is not enabled - rsh%"]
	name="Ensure rsh server is not enabled - rsh"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurershserverisnotenabledrlogin(CompliancePlugin):
	plugin_ids=["%Ensure rsh server is not enabled - rlogin%"]
	name="Ensure rsh server is not enabled - rlogin"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurershserverisnotenabledrexec(CompliancePlugin):
	plugin_ids=["%Ensure rsh server is not enabled - rexec%"]
	name="Ensure rsh server is not enabled - rexec"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureNISServerisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure NIS Server is not enabled%"]
	name="Ensure NIS Server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremailtransferagentisconfiguredforlocalonlymode(CompliancePlugin):
	plugin_ids=["%Ensure mail transfer agent is configured for local-only mode%"]
	name="Ensure mail transfer agent is configured for local-only mode"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSNMPServerisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure SNMP Server is not enabled%"]
	name="Ensure SNMP Server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureHTTPProxyServerisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure HTTP Proxy Server is not enabled%"]
	name="Ensure HTTP Proxy Server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureSambaisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure Samba is not enabled%"]
	name="Ensure Samba is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureIMAPandPOP3serverisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure IMAP and POP3 server is not enabled%"]
	name="Ensure IMAP and POP3 server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureHTTPserverisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure HTTP server is not enabled%"]
	name="Ensure HTTP server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureFTPServerisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure FTP Server is not enabled%"]
	name="Ensure FTP Server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureDNSServerisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure DNS Server is not enabled%"]
	name="Ensure DNS Server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureNFSandRPCarenotenabledRPC(CompliancePlugin):
	plugin_ids=["%Ensure NFS and RPC are not enabled - RPC%"]
	name="Ensure NFS and RPC are not enabled - RPC"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureNFSandRPCarenotenabledNFS(CompliancePlugin):
	plugin_ids=["%Ensure NFS and RPC are not enabled - NFS%"]
	name="Ensure NFS and RPC are not enabled - NFS"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureLDAPserverisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure LDAP server is not enabled%"]
	name="Ensure LDAP server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureDHCPServerisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure DHCP Server is not enabled%"]
	name="Ensure DHCP Server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureCUPSisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure CUPS is not enabled%"]
	name="Ensure CUPS is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureAvahiServerisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure Avahi Server is not enabled%"]
	name="Ensure Avahi Server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureXWindowSystemisnotinstalled(CompliancePlugin):
	plugin_ids=["%Ensure X Window System is not installed%"]
	name="Ensure X Window System is not installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurechronyisconfiguredOPTIONS(CompliancePlugin):
	plugin_ids=["%Ensure chrony is configured - OPTIONS%"]
	name="Ensure chrony is configured - OPTIONS"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurechronyisconfiguredNTPserver(CompliancePlugin):
	plugin_ids=["%Ensure chrony is configured - NTP server%"]
	name="Ensure chrony is configured - NTP server"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurentpisconfiguredOPTIONSorExecStartuntpntp(CompliancePlugin):
	plugin_ids=["%Ensure ntp is configured - OPTIONS or ExecStart -u ntp:ntp%"]
	name="Ensure ntp is configured - OPTIONS or ExecStart -u ntp:ntp"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsurentpisconfiguredNTPServer(CompliancePlugin):
	plugin_ids=["%Ensure ntp is configured - NTP Server%"]
	name="Ensure ntp is configured - NTP Server"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurentpisconfiguredrestrict6(CompliancePlugin):
	plugin_ids=["%Ensure ntp is configured - restrict -6%"]
	name="Ensure ntp is configured - restrict -6"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurentpisconfiguredrestrict4(CompliancePlugin):
	plugin_ids=["%Ensure ntp is configured - restrict -4%"]
	name="Ensure ntp is configured - restrict -4"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretimesynchronizationisinuse(CompliancePlugin):
	plugin_ids=["%Ensure time synchronization is in use%"]
	name="Ensure time synchronization is in use"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurexinetdisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure xinetd is not enabled%"]
	name="Ensure xinetd is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretftpserverisnotenabled(CompliancePlugin):
	plugin_ids=["%Ensure tftp server is not enabled%"]
	name="Ensure tftp server is not enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretimeservicesarenotenabledtimedgram(CompliancePlugin):
	plugin_ids=["%Ensure time services are not enabled - time-dgram%"]
	name="Ensure time services are not enabled - time-dgram"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuretimeservicesarenotenabledtimestream(CompliancePlugin):
	plugin_ids=["%Ensure time services are not enabled - time-stream%"]
	name="Ensure time services are not enabled - time-stream"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureechoservicesarenotenabledechodgram(CompliancePlugin):
	plugin_ids=["%Ensure echo services are not enabled - echo-dgram%"]
	name="Ensure echo services are not enabled - echo-dgram"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureechoservicesarenotenabledechostream(CompliancePlugin):
	plugin_ids=["%Ensure echo services are not enabled - echo-stream%"]
	name="Ensure echo services are not enabled - echo-stream"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurediscardservicesarenotenableddiscarddgram(CompliancePlugin):
	plugin_ids=["%Ensure discard services are not enabled - discard-dgram%"]
	name="Ensure discard services are not enabled - discard-dgram"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurediscardservicesarenotenableddiscardstream(CompliancePlugin):
	plugin_ids=["%Ensure discard services are not enabled - discard-stream%"]
	name="Ensure discard services are not enabled - discard-stream"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuredaytimeservicesarenotenableddaytimedgram(CompliancePlugin):
	plugin_ids=["%Ensure daytime services are not enabled - daytime-dgram%"]
	name="Ensure daytime services are not enabled - daytime-dgram"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuredaytimeservicesarenotenableddaytimestream(CompliancePlugin):
	plugin_ids=["%Ensure daytime services are not enabled - daytime-stream%"]
	name="Ensure daytime services are not enabled - daytime-stream"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurechargenservicesarenotenabledchargendgram(CompliancePlugin):
	plugin_ids=["%Ensure chargen services are not enabled - chargen-dgram%"]
	name="Ensure chargen services are not enabled - chargen-dgram"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurechargenservicesarenotenabledchargenstream(CompliancePlugin):
	plugin_ids=["%Ensure chargen services are not enabled - chargen-stream%"]
	name="Ensure chargen services are not enabled - chargen-stream"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureupdatespatchesandadditionalsecuritysoftwareareinstalled(CompliancePlugin):
	plugin_ids=["%Ensure updates, patches, and additional security software are installed%"]
	name="Ensure updates, patches, and additional security software are installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureGDMloginbannerisconfigurednotinstalled(CompliancePlugin):
	plugin_ids=["%Ensure GDM login banner is configured - not installed%"]
	name="Ensure GDM login banner is configured - not installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcissuenetareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/issue.net are configured%"]
	name="Ensure permissions on /etc/issue.net are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcissueareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/issue are configured%"]
	name="Ensure permissions on /etc/issue are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonetcmotdareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on /etc/motd are configured%"]
	name="Ensure permissions on /etc/motd are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureremoteloginwarningbannerisconfiguredproperly(CompliancePlugin):
	plugin_ids=["%Ensure remote login warning banner is configured properly%"]
	name="Ensure remote login warning banner is configured properly"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurelocalloginwarningbannerisconfiguredproperly(CompliancePlugin):
	plugin_ids=["%Ensure local login warning banner is configured properly%"]
	name="Ensure local login warning banner is configured properly"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremessageofthedayisconfiguredproperly(CompliancePlugin):
	plugin_ids=["%Ensure message of the day is configured properly%"]
	name="Ensure message of the day is configured properly"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureprelinkisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure prelink is disabled%"]
	name="Ensure prelink is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureaddressspacelayoutrandomizationASLRisenabled(CompliancePlugin):
	plugin_ids=["%Ensure address space layout randomization (ASLR) is enabled%"]
	name="Ensure address space layout randomization (ASLR) is enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureXDNXsupportisenabled(CompliancePlugin):
	plugin_ids=["%Ensure XD/NX support is enabled%"]
	name="Ensure XD/NX support is enabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurecoredumpsarerestrictedsysctl(CompliancePlugin):
	plugin_ids=["%Ensure core dumps are restricted - sysctl%"]
	name="Ensure core dumps are restricted - sysctl"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurecoredumpsarerestrictedlimitsconf(CompliancePlugin):
	plugin_ids=["%Ensure core dumps are restricted - limits.conf%"]
	name="Ensure core dumps are restricted - limits.conf"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureauthenticationrequiredforsingleusermodeemergencyservice(CompliancePlugin):
	plugin_ids=["%Ensure authentication required for single user mode - emergency.service%"]
	name="Ensure authentication required for single user mode - emergency.service"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensureauthenticationrequiredforsingleusermoderescueservice(CompliancePlugin):
	plugin_ids=["%Ensure authentication required for single user mode - rescue.service%"]
	name="Ensure authentication required for single user mode - rescue.service"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurebootloaderpasswordissetpassword_pbkdf2(CompliancePlugin):
	plugin_ids=["%Ensure bootloader password is set - password_pbkdf2%"]
	name="Ensure bootloader password is set - password_pbkdf2"
	risk_description=str()
	recommendation="Create an encrypted password with grub-mkpasswd-pbkdf2:\n\n# grub2-mkpasswd-pbkdf2\nEnter password: <password>\nReenter password: <password>\nYour PBKDF2 is <encrypted-password>\n\nAdd the following into /etc/grub.d/01_users or a custom /etc/grub.d configuration file:\n\ncat <<EOFset superusers=<username>password_pbkdf2 <username> <encrypted-password> EOF\n\nRun the following command to update the grub2 configuration:\n\n# grub2-mkconfig > /boot/grub2/grub.cfg"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurebootloaderpasswordissetsetsuperusers(CompliancePlugin):
	plugin_ids=["%Ensure bootloader password is set - set superusers%"]
	name="Ensure bootloader password is set - set superusers"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepermissionsonbootloaderconfigareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure permissions on bootloader config are configured%"]
	name="Ensure permissions on bootloader config are configured"
	risk_description=str()
	recommendation="Run the following commands to set permissions on the grub configuration:\n\n# chown root:root /boot/grub2/grub.cfg\n# chmod og-rwx /boot/grub2/grub.cfg"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurefilesystemintegrityisregularlychecked(CompliancePlugin):
	plugin_ids=["%Ensure filesystem integrity is regularly checked%"]
	name="Ensure filesystem integrity is regularly checked"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureAIDEisinstalled(CompliancePlugin):
	plugin_ids=["%Ensure AIDE is installed%"]
	name="Ensure AIDE is installed"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureRedHatNetworkorSubscriptionManagerconnectionisconfigured(CompliancePlugin):
	plugin_ids=["%Ensure Red Hat Network or Subscription Manager connection is configured%"]
	name="Ensure Red Hat Network or Subscription Manager connection is configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsureGPGkeysareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure GPG keys are configured%"]
	name="Ensure GPG keys are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuregpgcheckisgloballyactivated(CompliancePlugin):
	plugin_ids=["%Ensure gpgcheck is globally activated%"]
	name="Ensure gpgcheck is globally activated"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurepackagemanagerrepositoriesareconfigured(CompliancePlugin):
	plugin_ids=["%Ensure package manager repositories are configured%"]
	name="Ensure package manager repositories are configured"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids DisableAutomounting(CompliancePlugin):
	plugin_ids=["%Disable Automounting%"]
	name="Disable Automounting"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurestickybitissetonallworldwritabledirectories(CompliancePlugin):
	plugin_ids=["%Ensure sticky bit is set on all world-writable directories%"]
	name="Ensure sticky bit is set on all world-writable directories"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenoexecoptionsetondevshmpartition(CompliancePlugin):
	plugin_ids=["%Ensure noexec option set on /dev/shm partition%"]
	name="Ensure noexec option set on /dev/shm partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenosuidoptionsetondevshmpartition(CompliancePlugin):
	plugin_ids=["%Ensure nosuid option set on /dev/shm partition%"]
	name="Ensure nosuid option set on /dev/shm partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenodevoptionsetondevshmpartition(CompliancePlugin):
	plugin_ids=["%Ensure nodev option set on /dev/shm partition%"]
	name="Ensure nodev option set on /dev/shm partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenodevoptionsetonhomepartition(CompliancePlugin):
	plugin_ids=["%Ensure nodev option set on /home partition%"]
	name="Ensure nodev option set on /home partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenoexecoptionsetonvartmppartition(CompliancePlugin):
	plugin_ids=["%Ensure noexec option set on /var/tmp partition%"]
	name="Ensure noexec option set on /var/tmp partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenosuidoptionsetonvartmppartition(CompliancePlugin):
	plugin_ids=["%Ensure nosuid option set on /var/tmp partition%"]
	name="Ensure nosuid option set on /var/tmp partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenodevoptionsetonvartmppartition(CompliancePlugin):
	plugin_ids=["%Ensure nodev option set on /var/tmp partition%"]
	name="Ensure nodev option set on /var/tmp partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenoexecoptionsetontmppartition(CompliancePlugin):
	plugin_ids=["%Ensure noexec option set on /tmp partition%"]
	name="Ensure noexec option set on /tmp partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenosuidoptionsetontmppartition(CompliancePlugin):
	plugin_ids=["%Ensure nosuid option set on /tmp partition%"]
	name="Ensure nosuid option set on /tmp partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensurenodevoptionsetontmppartition(CompliancePlugin):
	plugin_ids=["%Ensure nodev option set on /tmp partition%"]
	name="Ensure nodev option set on /tmp partition"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids EnsuremountingofFATfilesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of FAT filesystems is disabled%"]
	name="Ensure mounting of FAT filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremountingofudffilesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of udf filesystems is disabled%"]
	name="Ensure mounting of udf filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremountingofsquashfsfilesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of squashfs filesystems is disabled%"]
	name="Ensure mounting of squashfs filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremountingofhfsplusfilesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of hfsplus filesystems is disabled%"]
	name="Ensure mounting of hfsplus filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremountingofhfsfilesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of hfs filesystems is disabled%"]
	name="Ensure mounting of hfs filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremountingofjffs2filesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of jffs2 filesystems is disabled%"]
	name="Ensure mounting of jffs2 filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremountingoffreevxfsfilesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of freevxfs filesystems is disabled%"]
	name="Ensure mounting of freevxfs filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap


	# New plugin_ids Ensuremountingofcramfsfilesystemsisdisabled(CompliancePlugin):
	plugin_ids=["%Ensure mounting of cramfs filesystems is disabled%"]
	name="Ensure mounting of cramfs filesystems is disabled"
	risk_description=str()
	recommendation=str()

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices