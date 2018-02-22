from plugins import genFile

def gen(cb):
	notes=str()
	description=str()

	# New plugin_ids PasswordPolicyMinDiff(CompliancePlugin):
	plugin_ids=["%/etc/security/user - mindiff%"]
	name="Local Password Policy: Minimum Differing Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"mindiff\" attribute is used to enforce that a minimum number of new characters that were not in the previous password must be included in new password. In setting this attribute, users are not able to reuse the same or immediately similar passwords."
	recommendation="Set the \"mindiff\" attribute in /etc/security/user in line with an agreed internal policy. A value of 4 is recommended and can be set using the following command:\n\nchsec -f /etc/security/user -s default -a mindiff=4"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinAge(CompliancePlugin):
	plugin_ids=["%/etc/security/user - minage%"]
	name="Local Password Policy: Minimum Age"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"minage\" attribute is used to enforce the minimum age of a newly set password. This value is controlled in number of weeks, so the lowest value prevents a user from changing their password for one week. This setting prevents users from constantly changing their passwords to bypass other password policy controls and reusing the same password permanently."
	recommendation="Set the \"minage\" attribute in /etc/security/user to at least 1 using the following command:\n\nchsec -f /etc/security/user -s default -a minage=1"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMaxAge(CompliancePlugin):
	plugin_ids=["%/etc/security/user - maxage%"]
	name="Local Password Policy: Maximum Age"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"maxage\" attribute is used to enforce the maximum age (in weeks) that a newly set password is valid for (until it is forced to be reset). This setting prevents users from continuing to use the same password for an extended period of time (or idefinitely). Prolonged use of the same password is typically seen to leave it increasingly prone to compromise."
	recommendation="Set the \"maxage\" attribute in /etc/security/user in line with an agreed internal policy. Recommended settings fall around 90 days (or 13 weeks), so the following command could be used to suitably set this policy:\n\nchsec -f /etc/security/user -s default -a maxage=13"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinLen(CompliancePlugin):
	plugin_ids=["%/etc/security/user - minlen%"]
	name="Local Password Policy: Minimum Length"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"minlen\" attribute is used to enforce the minimum length/number of characters required in a local users password. Forcing the use of increased length passwords is seen to increase their resilience to brute-force attacks."
	recommendation="Set the \"minlen\" attribute in /etc/security/user in line with an agreed internal policy. Recommended settings for standard user passwords is 8 characters whilst administrative users should use 14 characters. The following command could be used to suitably set this policy in line with the administrative user policy:\n\nchsec -f /etc/security/user -s default -a minlen=14"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinAlpha(CompliancePlugin):
	plugin_ids=["%/etc/security/user - minalpha%"]
	name="Local Password Policy: Mandatory Alphabetic Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"minalpha\" attribute is used to enforce the minimum number of alphabetic characters in local user passwords and can be used, in tandem with other settings, to ensure password are configured in line within an organisations policies.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"minalpha\" attribute in /etc/security/user to at least 2 using the following command:\n\nchsec -f /etc/security/user -s default -a minalpha=2"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinOther(CompliancePlugin):
	plugin_ids=["%/etc/security/user - minother%"]
	name="Local Password Policy: Mandatory Non-Alphabetic Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"minother\" attribute is used to enforce the minimum number of non-alphabetic characters in local user passwords and can be used, in tandem with other settings, to ensure password are configured in line within an organisations policies.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"minother\" attribute in /etc/security/user to at least 2 using the following command:\n\nchsec -f /etc/security/user -s default -a minother=2"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMaxRepeats(CompliancePlugin):
	plugin_ids=["%/etc/security/user - maxrepeats%"]
	name="Local Password Policy: Maximum Repeated Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"maxrepeats\" attribute is used to enforce the maximum number of the same character that can be used in local user passwords and can be used, in tandem with other settings, to ensure password are configured in line within an organisations policies.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"maxrepeats\" attribute in /etc/security/user to 2 using the following command:\n\nchsec -f /etc/security/user -s default -a maxrepeats=2"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyHistExpire(CompliancePlugin):
	plugin_ids=["%/etc/security/user - histexpire%"]
	name="Local Password Policy: Password History Expiry"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"histexpire\" attribute is used to enforce the length of time in which a user is not allowed to reuse a previously set password. This prevents users from resetting passwords repeatedly in an attempt to reuse the same password.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"histexpire\" attribute in /etc/security/user in line with organisational policies. A value of 13 is typically recommended:\n\nchsec -f /etc/security/user -s default -a histexpire=13"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyHistSize(CompliancePlugin):
	plugin_ids=["%/etc/security/user - histsize%"]
	name="Local Password Policy: Password History Size"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"histsize\" attribute is used to enforce the number of previously used passwords for a user that the host remembers. This is used to prevent password reuse by a user resetting passwords repeatedly in an attempt to reuse the same password.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"histsize\" attribute in /etc/security/user in line with organisational policies. A value of 20 is typically recommended:\n\nchsec -f /etc/security/user -s default -a histsize=20"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMaxExpired(CompliancePlugin):
	plugin_ids=["%/etc/security/user - maxexpired%"]
	name="Local Password Policy: Maximum Expired Age"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"maxexpired\" attribute is used to control how long after a password has expired that the user can reset it themselves. Setting this policy limits this timeframe to a set number of weeks and can prevent unused user accounts from remaining active on a system even after the password has expired.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"maxexpired\" attribute in /etc/security/user in line with organisational policies. A value of 2 is typically recommended:\n\nchsec -f /etc/security/user -s default -a maxexpired=2"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinLowerAlpha(CompliancePlugin):
	plugin_ids=["%/etc/security/user - minloweralpha%"]
	name="Local Password Policy: Mandatory Lower-Case Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"minloweralpha\" attribute is used to enforce the presence of lower-case alphabetic characters in local user passwords and can be used, in tandem with other settings, to ensure password are configured in line within an organisations policies.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"minloweralpha\" attribute in /etc/security/user to at least 1 using the following command:\n\nchsec -f /etc/security/user -s default -a minloweralpha=1"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinUpperAlpha(CompliancePlugin):
	plugin_ids=["%/etc/security/user - minupperalpha%"]
	name="Local Password Policy: Mandatory Upper-Case Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"minupperalpha\" attribute is used to enforce the presence of upper-case alphabetic characters in local user passwords and can be used, in tandem with other settings, to ensure password are configured in line within an organisations policies.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"minupperalpha\" attribute in /etc/security/user to at least 1 using the following command:\n\nchsec -f /etc/security/user -s default -a minupperalpha=1"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinDigit(CompliancePlugin):
	plugin_ids=["%/etc/security/user - mindigit%"]
	name="Local Password Policy: Mandatory Numeric Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"mindigit\" attribute is used to enforce the presence of numeric characters in local user passwords and can be used, in tandem with other settings, to ensure password are configured in line within an organisations policies.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"mindigit\" attribute in /etc/security/user to at least 1 using the following command:\n\nchsec -f /etc/security/user -s default -a mindigit=1"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PasswordPolicyMinSpecial(CompliancePlugin):
	plugin_ids=["%/etc/security/user - minspecialchar%"]
	name="Local Password Policy: Mandatory Special Characters"
	risk_description="The local password policy is controlled by the settings within /etc/security/user. The \"minspecialchar\" attribute is used to enforce the presence of special (e.g. punctuation characters in local user passwords and can be used, in tandem with other settings, to ensure password are configured in line within an organisations policies.\n\nThis attribute is currently not set to a suitable value."
	recommendation="Set the \"minspecialchar\" attribute in /etc/security/user to at least 1 using the following command:\n\nchsec -f /etc/security/user -s default -a /etc/security/user - minspecialchar=1"

	#####Security
	###Section 3.2

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SecurityLoginRetries(CompliancePlugin):
	plugin_ids=["%/etc/security/user - loginretries%"]
	name="Security Configuration: Login Retries"
	risk_description="The \"loginretries\" setting in /etc/security/user can be used to restrict the number of failed login attempts a user has before their account is locked account. This setting can offer further mitigation against brute-froce attacks by preventing an attacker from actually logging into a locker user account. It does also carry a risk of denial of service, either accidentally by a forgetful user or on purpose by a malicious user. Currently this attribute is not suitably set and user accounts are not locked out regardless of number of authentication failures."
	recommendation="It is recommended to set the \"loginretries\" attribute in /etc/security/user to 3, as outlined in the following command:\n\n chsec -f /etc/security/user -s default -a loginretries=3"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SecurityRlogin(CompliancePlugin):
	plugin_ids=["%/etc/security/user - rlogin%"]
	name="Security Configuration: rlogin"
	risk_description="The \"rlogin\" setting in /etc/security/user can be used to prevent the \"root\" account being using to directly log into the host remotely. Permitting remote root logins leaves the host increasingly susceptible to compromise, particularly in the case of a malicious host masquerading as an intended destination host intercepting root credentials or direct brute-force attacks. The current setting on this host permits such actions."
	recommendation="It is recommended to set the \"rlogin\" attribute in /etc/security/user to \"false\", as outlined in the following command:\n\nchsec -f /etc/security/user -s root -a rlogin=false"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SecuritySuGroups(CompliancePlugin):
	plugin_ids=["%/etc/security/user - sugroups%"]
	name="Security Configuration: sugroups"
	risk_description="The \"sugroups\" setting in /etc/security/user can be used to restrict access to the \"root\" account using the \"su\" command to users who are members of a specific group. Configuring this setting is seen to offer an additional mitigation against a complete host compromise as an attacker would need to compromise a user in the \"sugroups\" configured group in order to then use \"su\" to change to the \"root\" user using a compromise \"root\" user password.\n\nCurrently this attribute is set to the default value of \"ALL\", allowing all users to invoke \"su\" to root (although still requiring a valid password)."
	recommendation="It is recommended to set the \"sugroups\" attribute in /etc/security/user to \"system\", as outlined in the following command:\n\nchuser su=true sugroups=system root"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SecurityTelnet(CompliancePlugin):
	plugin_ids=["%/etc/inetd.conf - telnet%"]
	name="Security Configuration: Telnet Service"
	risk_description="An entry for \"telnetd\" is present in the /etc/inetd.conf file. This entry starts the telnetd daemon when required, providing a remote command line service which does not implement encryption by default, resulting in all service traffic, including usernames and passwords, being passed over the network in clear text, leaving them susceptible to interception.\n\nIt would be noted that the host was seen to have SSH enabled, which offers the same functionality as telnet except over encrypted connections. The presence of this configuration may therefore be a result of legacy configuration."
	recommendation="Review the /etc/inetd.conf file for any entries containing \"telnet\" (e.g. \"chsubserver -r inetd -C /etc/inetd.conf -d -v telnet -p tcp6\") and remove/comment out the offending lines.\n\nUse an alternative remote access service (e.g. SSH)."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SecurityFTP(CompliancePlugin):
	plugin_ids=["%/etc/inetd.conf - FTP%"]
	name="Security Configuration: FTP Service"
	risk_description="An entry for \"ftp\" is present in the /etc/inetd.conf file. This entry starts the ftp daemon when required, providing a file sharing service to networked hosts. By default, FTP does not implement encryption, resulting in all service traffic, including usernames and passwords, being passed over the network in clear text, leaving them susceptible to interception (or manipulation.\n\nIt would be noted that the host was seen to have SSH enabled, which offers similar functionality as FTP within its SFTP subsystem except over encrypted connections. The presence of this configuration may therefore be a result of a legacy configuration (e.g. older clients or software are only able to use FTP services)."
	recommendation="Review the /etc/inetd.conf file for any entries containing \"ftp\" (e.g. \"chsubserver -r inetd -C /etc/inetd.conf -d -v ftp -p tcp6\") and remove/comment out the offending lines."


	#####Miscellaneous Enhancements
	###Section 3.7

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MiscellaneousEnhancementCrontabPermissions(CompliancePlugin):
	plugin_ids=["%crontab permissions%"]
	name="Miscellaneous Enhancements: Crontab Permissions"
	risk_description="It is recommended that all root crontab entries be owned and writable by the root user only. Scripts with group or world writable access and non root-only permissions can potentially be replaced or edited with malicious content, which would then subsequently run on the system with root authority providing a potential mechanism for privilege escalation.\n\nThe following scripts/directories seen within crontabs have non root-only permissions:\n\n#########"
	recommendation="Review and manually change permissions to root-only on the identified files/directories.\n\nRemove group writable access from a resource using: chmod g-w <name>\n\nRemove world-writable access from resource using: chmod o-w <name>\n\nTo remove both group and world-writable access from resources use: chmod go-w <name>\n\nTo change the owner of a file or directory use: chown <new user> <name>"

	#####SSH Configuration
	####Section 4.2

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationDisableDirectRoot(CompliancePlugin):
	plugin_ids=["%Configuring SSH - disabling direct root access%"]
	name="Configuring SSH: Disable Direct root Access"
	risk_description="The host permits remote connections to the SSH service to be established as \"root\". Best practice recommends that direct remote access to an SSH session on a host as the \"root\" user not be permitted. As a persistent and privileged account across all hosts, permitting SSH logins as \"root\" could leave the account susceptible to brute-force attacks and offers little in the way of audit trailing for accountability.\n\nIdeally all root access should be facilitated through a separate logon with a unique and identifiable user ID and then via the su command once locally authenticated. Direct root login is extremely insecure.\n\nThe current configuration is reflect of default settings for AIX hosts."
	recommendation="Edit the /etc/ssh/sshd_config file and change/add the \"PermitRootLogin\" entry with the following value:\n\n PermitRootLogin no\n\nRestart the sshd daemon to apply this configuration change."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationProtocol2(CompliancePlugin):
	plugin_ids=["%Configuring SSH - server protocol 2%","%Configuring SSH - server protocol - Protocol 2%"]
	name="Configuring SSH: Server Protocol Version"
	risk_description="The SSH server configuration on the host does not specify a requirement for SSH connections to only use SSH protocol version 2 in the /etc/ssh/sshd_config file. This potentially allows connections to the SSH service using SSH protocol version 1, which is associated with a number of publicly disclosed vulnerabilities, resulting in it being deprecated. Support for and use of this protocol increase the risk posed to service traffic and the host."
	recommendation="Edit the /etc/ssh/sshd_config file and change/add the \"Protocol\" entry with the following value:\n\n Protocol 2\n\nRestart the sshd daemon to apply this configuration change."

	####Have left out findings relating to banners at the moment

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationIgnoreShostsRhosts(CompliancePlugin):
	plugin_ids=["%Configuring SSH - ignore .shosts and .rhosts%"]
	name="Configuring SSH: Ignore .shosts and .rhosts"
	risk_description="The current SSH configuration on the host could make it possible for a user to logon to it remotely without authenticating themselves, provided that .rhosts or .shosts files exist in their home directory on the host and if the connecting client machine name and user name are present in these files. This method is fundamentally insecure as the host could be exploited by IP, DNS (Domain Name Server) and routing spoofing attacks. Additionally, this authentication method relies on the integrity of the client machine. These weaknesses have been known and exploited for a long time.\n\nIt is possible to prevent this behaviour within the SSH configuration using the \"IgnoreRhosts\" option, which is not suitably set on this host. It should also be noted that a user would actively have to configure the .rhosts or .shosts files in their home directory and so would require authenticated access to the host to do so."
	recommendation="Edit the /etc/ssh/sshd_config file and change/add the \"IgnoreRhosts\" entry with the following value:\n\nIgnoreRhosts yes\n\nRestart the sshd daemon to apply this configuration change."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationDisableNullPasswords(CompliancePlugin):
	plugin_ids=["%Configuring SSH - disable null passwords%"]
	name="Configuring SSH: Disable Null Passwords"
	risk_description="The current SSH configuration on the host is not set to prevent user accounts with a null/empty password value from authenticating and connecting to the host via the SSH service. Permitting the use of empty passwords via SSH could create an simple path of access for attackers targeting the system.\n\nIt is possible to prevent this behaviour within the SSH configuration using the \"PermitEmptyPasswords\" option, which is not suitably set on this host."
	recommendation="Edit the /etc/ssh/sshd_config file and change/add the \"PermitEmptyPasswords\" entry with the following value:\n\nPermitEmptyPasswords No\n\nRestart the sshd daemon to apply this configuration change.\n\nAdditionally, ensure that no user accounts are set with null/empty passwords."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationSetLogLevelInfo(CompliancePlugin):
	plugin_ids=["%Configuring SSH - set LogLevel to INFO%"]
	name="Configuring SSH: Set LogLevel to INFO"
	risk_description="The \"LogLevel\" attribute is used to determine what, if any, data is collected about the usage of an SSH service. Setting this attribute to \"INFO\" ensures that some logging is being performed on the service, primarily relating to user sessions, logins and logouts. This information can be useful when attempting to investigate an incident as it can allow the identification of active users on the host.\n\nNote:This finding is recorded as the LogLevel is not set to \"INFO\". SSH provides various logging levels which can each be useful for specific purposes. If an alternative setting (e.g. \"VERBOSE\" or \"DEBUG\") is currently in use on the hosts SSH service and is required then thi	s finding can be considered a false-positive."
	recommendation="Edit the /etc/ssh/sshd_config file and change/add the \"LogLevel\" entry with the following value (or one which falls in line with organisational policy):\n\nLogLevel INFO\n\nRestart the sshd daemon to apply this configuration change."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationMaxAuthTries(CompliancePlugin):
	plugin_ids=["%Configuring SSH - set MaxAuthTries to 4 or Less%"]
	name="Configuring SSH: MaxAuthTries"
	risk_description="The \"MaxAuthTries\" attribute defines the maximum number of authentication attempts permitted per connection. When the login failure count reaches half this number, error messages will be written to the syslog file detailing the login failure, allowing the identification of potential brute force attacks. Setting this attribute to a suitably low value also helps to hinder such attack attempts by limiting the rate at which authentication attempts can be made. The current setting is seen to be above the recommended value of 4; however, this value should be set in line with organisational policies."
	recommendation="Edit the /etc/ssh/sshd_config file and change the \"MaxAuthTries\" entry with the following value (or one which falls in line with organisational policy):\n\nMaxAuthTries 4\n\nRestart the sshd daemon to apply this configuration change."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationIdleTimeout(CompliancePlugin):
	plugin_ids=["%Configuring SSH - set Idle Timeout Interval for User Login - ClientAliveCountMax%","%Configuring SSH - set Idle Timeout Interval for User Login - ClientAliveInterval%"]
	name="Configuring SSH: Idle Session Timeout"
	risk_description="The \"ClientAliveCountMax\" and \"ClientAliveInternal\" attributes are used to control the timeout of idle SSH sessions. When the \"ClientAliveInterval\" variable is set, SSH sessions that have no activity for the specified length of time are terminated. When the \"ClientAliveCountMax\" variable is set, sshd will send client alive messages at every \"ClientAliveInterval\" interval. When the number of consecutive client alive messages are sent with no response from the client, the SSH session is terminated. This configuration helps to prevent various attack vectors, including those which leverage access to an authorised users client which has an active yet unused SSH session to the host, by terminating unused connections."
	recommendation="Edit the /etc/ssh/sshd_config file and change the \"ClientAliveCountMax\" and \"ClientAliveInterval\"entries with the following value (or those which falls in line with organisational policy):\n\n ClientAliveCountMax 0\nClientAliveInterval 300\n\nRestart the sshd daemon to apply this configuration change."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationCipherList(CompliancePlugin):
	plugin_ids=["%Configuring SSH - restrict Cipher list%"]
	name="Configuring SSH: Restrict Cipher List"
	risk_description="The list of ciphers which an SSH service allows connections to be established with can be configured using the \"Ciphers\" attribute in /etc/ssh/sshd_config. Setting this value to only support secure ciphers part of SSH service hardening. Known security weaknesses can allow the recovery of up to 32 bits of plaintext from a block of ciphertext that was encrypted with the Cipher Block Chaining (CBC) method, so support for such ciphers is not seen to reflect strong security practice; however, the risk presented by using these ciphers, particularly in limited access environments, is seen to be limited due to exploitation prerequisites. Ciphers using counter mode algorithms are now recommended for standard use."
	recommendation="Edit the /etc/ssh/sshd_config file and set the \"Ciphers\" attribute to the following:\n\nCiphers aes128-ctr,aes192-ctr,aes256-ctr"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationPermitUserEnvironment(CompliancePlugin):
	plugin_ids=["%Configuring SSH - ignore user-provided environment variables%"]
	name="Configuring SSH: Ignore User-Provided Environment Variables"
	risk_description="The \"PermitUserEnvironment\" option allows users to present environment options to the ssh daemon. Permitting users the ability to set environment variables through the SSH daemon could potentially allow the bypass of security controls (e.g. setting an execution path that has ssh executing malicious programs), leading to privilege escalation attacks/host compromise. This attribute is not suitably configured to prevent such activity on this host."
	recommendation="Edit the /etc/ssh/sshd_config file and set the \"PermitUserEnvironment\" attribute to the following:\n\nPermitUserEnvironment no"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids SSHConfigurationSSHDConfigPermissions(CompliancePlugin):
	plugin_ids=["%Configuring SSH - sshd_config permissions lockdown%"]
	name="Configuring SSH: sshd_config permissions"
	risk_description="The SSH daemon reads the configuration information from the /etc/ssh/sshd_config file, including the authentication mode and cryptographic levels to use during SSH communication. It is recommended that the permissions for this file be configured to prevent any access from any user other than the owner of the file (typically root). Read only access to this file presents a reduced risk but could reveal unique configurations, such as which users are permitted to access the service or whether users may set their own environment variables. Write access would permit a user to alter these values, which could enable complete host compromise."
	recommendation="Alter the permissions of the /etc/ssh/sshd_config file to prevent unneccessary access. The following command will implement this configuration:\n\nchmod u=rw,go= /etc/ssh/sshd_config"



	#####Mail Configuration?
	####Section 4.3

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MailConfigurationGreeting(CompliancePlugin):
	plugin_ids=["%/etc/mail/sendmail.cf - SmtpGreetingMessage%"]
	name="Sendmail: Greeting Message"
	risk_description="The current Sendmail configuration on the host presents the default greeting message. This will include the underlying version of Sendmail in use on the host and can be used to better fingerprint the host and target attacks against a specific software version.\n\nNote that this configuration presents minimal risk if the host is not actively presenting mail services to other hosts."
	recommendation="Edit the \"/etc/mail/sendmail.cf\" file and alter the \"SmtpGreetingMessage\" entry so that it displays a generic response. A recommended value is shown below:\n\nSmtpGreetingMessage=mailerready"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MailConfigurationPermissions(CompliancePlugin):
	plugin_ids=["%/etc/mail/sendmail.cf - permissions and ownership%"]
	name="Sendmail: Configuration File Permissions"
	risk_description="The permissions set on the Sendmail configuration file (\"/etc/mail/sendmail.cf\") are seen to be overly permissive and allow unnecessary users to access its content. As this file is used to hold the Sendmail daemons default configuration, unauthorised access presents a risk to the daemon and the system. It would be noted that this finding is seen to present a reduced risk where only read access is permitted to lower-privilege users and if the host is not actively being used to provide mail services."
	recommendation="Set the permissions on the \"/etc/mail/sendmail.cf\" file to limit access to its contents. The following commands would implement a suitable configuration:\n\nchmod u=rw,g=r,o= /etc/mail/sendmail.cf\nchown root /etc/mail/sendmail.cf"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MailConfigurationVarSpoolMqueue(CompliancePlugin):
	plugin_ids=["%/var/spool/mqueue - permissions and ownership%"]
	name="Sendmail: Mqueue Permissions"
	risk_description="The permissions set on the \"/var/spool/mqueue\" directory, used to store queued mail before it is sent out, could permit non-root users to access the directory contents. This could include reading sensitive mail contents or altering messages before they are sent. Sendmail configuration file (\"/etc/mail/sendmail.cf\") are seen to be overly permissive and allow unnecessary users to access its content. It would be noted that this finding is seen to present a reduced risk where only read access is permitted to lower-privilege users and if the host is not actively being used to provide mail services."
	recommendation="Set the permissions on the \"/var/spool/mqueue\" directory to prevent non-root users from accessing its contents. The following commands would implement a suitable configuration:\n\nchmod u=rwx,go= /var/spool/mqueue\nchown root /var/spool/mqueue"

	#####NFS Configuration
	####Section 4.5

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids NFSConfigurationNosuidClientMounts(CompliancePlugin):
	plugin_ids=["%NFS - nosuid on NFS client mounts%"]
	name="NFS Configuration: nosuid on NFS client mounts"
	risk_description="The hosts configuration does not disable the execution of suid or sgid programs which exist on a mounted NFS filesystem. By setting the nosuid option on the NFS server the root user cannot make an suid-root program within an exported filesystem which could lead to a potential privilege escalation vector by providing a standard user accessing the service with an NFS client to use the suid-root program to execute a program as root on their client.\n\nThis issue is highlighted as the server facilitates such activity with its current configuration but is not necessarily vulnerable to a privilege escalation attack."
	recommendation="The options settings for each NFS mount can be suitably altered in the \"/etc/filesystems\" file by adding the \"nosuid\" value. The following is an example of a suitable entry:\n\noptions = rw,bg,hard,intr,nosuid,sec=sys\n\nThis change should be actoned for existing options settings and alter NFS mounts will need to be re-mounted to apply this change."

	#####File Permissions/Ownership
	####Section 4.11

	###???Need to check this one as theres a check for whether the file actually exists

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	## New plugin_ids PermissionsSmitLog(CompliancePlugin):
	#	plugin_ids=["%Permissions and Ownership - /smit.log%"]
	#	name="File Permissions: /smit.log"
	#	risk_description=str()
	#	recommendation=str()

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsVarAdmCronLog(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - /var/adm/cron/log%","%Permissions and Ownership - /var/adm/cron/log root:cron 660"]
	name="File Permissions: /var/adm/cron/log"
	risk_description="The \"/var/adm/cron/log\" file contains a log of all cron jobs run on the system. As this file could contain sensitive information it is recommended that it only be accessible to its owner and group. The observed permissions were not seen to be in line with this recommendation."
	recommendation="Remove world read and write access to /var/adm/cron/log using the following command:\n\nchmod o-rw /var/adm/cron/log"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsVarSpoolCronCrontabsFiles(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - /var/spool/cron/crontabs - files%","%Permissions and Ownership - /var/spool/cron/crontabs/ root:cron 770"]
	name="File Permissions: /var/spool/cron/crontabs"
	risk_description="The \"/var/spool/cron/crontabs\" directory contains all of the crontabs for the users on the system. Crontab files present a security problem because they are run by the cron daemon, which runs with super user rights. Allowing other users to have read/write permissions on these files may allow them to escalate their privileges. To negate this risk, the directory and all the files that it contains must be suitably secured. Files within this directory were seen to have unsuitable configurations and should be reviewed."
	recommendation="Review each crontab file and ensure their permissions are suitably configured. The following commands are seen to provide a recommended configuration for the contents of the \"/var/spool/cron/crontabs\" directory:\n\nchmod -R o= /var/spool/cron/crontabs\nchmod ug=rwx,o= /var/spool/cron/crontabs\nchgrp -R cron /var/spool/cron/crontabs"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsVarAdmCronAtAllow(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - /var/adm/cron/at.allow%","%Permissions and Ownership - /var/adm/cron/at.allow root:sys 400"]
	name="File Permissions: /var/adm/cron/at.allow"
	risk_description="The \"/var/admin/cron/at.allow\" file controls which users can schedule jobs via the \"at\" command. This is typically recommended to be set so that only the \"root\" user has the permissions to create, edit, or delete this file as it could provide a mechanism for privilege escalation; however, the current permissions are not seen to reflect this."
	recommendation="Review the current permissions and ownership applied to this file. Unless it is in line with expected settings (i.e. manually set as part of a confirmed host build) alter the permissions in line with the recommended settings. These permissions can be implemented using the following commands:\n\nchown root:sys /var/adm/cron/at.allow\nchmod u=r,go= /var/adm/cron/at.allow"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsVarAdmCronCronAllow(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - /var/adm/cron/cron.allow%","%Permissions and Ownership - /var/adm/cron/cron.allow root:sys 400%"]
	name="File Permissions: /var/adm/cron/cron.allow"
	risk_description="The \"/var/admin/cron/cron.allow\" file controls which users can schedule jobs via the \"cron\" command. This is typically recommended to be set so that only the \"root\" user has the permissions to create, edit, or delete this file as it could provide a mechanism for privilege escalation; however, the current permissions are not seen to reflect this."
	recommendation="Review the current permissions and ownership applied to this file. Unless it is in line with expected settings (i.e. manually set as part of a confirmed host build) alter the permissions in line with the recommended settings. These permissions can be implemented using the following commands:\n\nchown root:sys /var/adm/cron/cron.allow\nchmod u=r,go= /var/adm/cron/cron.allow"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsVarAdmRas(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - /var/adm/ras%","%Permissions and Ownership - /var/adm/ras/* files are not world readable or writable"]
	name="File Permissions: /var/adm/ras"
	risk_description="The \"/var/admin/ras\" directory contains log files including those relating to sensitive data, such as user logins (including timestamps) and IP addresses. Providing access to such information can assist an attacker/malicious user in targeting attacks against other users and provide the ability to remove evidence of their activity on a host from local logs. This can be somewhat mitigated if host logs are sent to a centralised monitoring solution."
	recommendation="Review the permissions of each file in this directory and alter them so only authorised users have read and write access to them. The following command is recommended to apply a suitable configuration for all files in the directory:\n\nchmod o-rw /var/adm/ras/*"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsVarCtRMstart(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - /var/ct/RMstart.log%","%Permissions and Ownership - /var/ct/RMstart.log root:system 640"]
	name="File Permissions: /var/ct/RMstart.log"
	risk_description="RMC provides a single monitoring and management infrastructure for both RSCT peer domains and management domains. Its generalised framework is used by cluster management tools to monitor, query, modify, and control cluster resources, /var/ct/RMstart.log is the logfile used by RMC and can contain sensitive data that must be secured from unauthorised access. The current permissions set on the file on this host leave it accessible to other users on the host."
	recommendation="Review the permissions of the file. The following command is recommended to apply a suitable configuration:\n\nchmod o-rw /var/ct/RMstart.log"

	####Need to review for when "file does not exist"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	## New plugin_ids PermissionsVarTmp/Dpid2(CompliancePlugin):
	#	plugin_ids=["%Permissions and Ownership - /var/tmp/dpid2.log%"]
	#	name="File Permissions: /var/tmp/dpid2.log"
	#	risk_description="The /var/tmp/dpid2.log logfile is used by the dpid2 daemon and can contain sensitive SNMP information. As SNMP can be used to monitor and alter system settings the contents of this file must be suitably secured from unauthorised access and modification. The impact presented by unsuitable permissions being set on this log file is somewhat limited based on its contents (i.e. if SNMP is not in use and therefore not generating logs then this finding presents a reduced risk). Current permissions set on the file are not seen to be in line with best practice recommendations:\n\n###########"
	#	recommendation="Review the permissions of the file. The following command is recommended to apply a suitable configuration:\n\nchmod o-rw /var/ct/RMstart.log"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsVarAdmSa(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - /var/adm/sa%","%Permissions and Ownership - /var/adm/sa adm:adm 755"]
	name="File Permissions: /var/adm/sa"
	risk_description="The /var/adm/sa directory holds the performance data in report files produced by the system activity reporter (\"sar\") utility. This utility can be used by administrative users to collect data about system performance metrics, the contents of which may be sensitive or could identify a system performance issue (presenting a possible denial-of-service vector). The contents of this directory are therfore considered sensitive and should be secured from unauthorised access."
	recommendation="Review the permissions of the file. The following commands are recommended to apply a suitable configuration:\n\nchown adm:adm /var/adm/sa\nchmod u=rwx,go=rx /var/adm/sa"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsHomeConfig(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - home directory configuration files%"]
	name="File Permissions: Home Directory Configuration Files"
	risk_description="Files have been identified within user home directories which use the \".\" prefix, which is commonly used to identify configuration files (as well as marking the files as hidden). Group- or world-writeable user configuration files in a home directory could enable malicious users to steal or modify other users data, or to gain elevated privileges, by introducing malicious content into files which are parsed by other programs, such as when a user logs on.\n\nThe following files were identified:\n\n#############"
	recommendation="Review the permissions and presence of each file. Remove any unnecessary files and alter the permissions of required files to prevent unauthorised access. The following command is recommended to apply a suitable configuration:\n\nchmod go-w <File>\n\nNote: The following script may be used to automate this process:\n\nlsuser -a home ALL |cut -f2 -d= | while read HOMEDIR; do\necho Examining $HOMEDIR\nif [ -d $HOMEDIR ]; then\nls -a $HOMEDIR | grep -Ev ^.$|^..$ |\nwhile read FILE; do\n if [ -f $FILE ]; then\nls -l $FILE\nchmod go-w $FILE\nfi\ndone\nelse\necho No home dir for $HOMEDIR\nfi\ndone"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsHomeDirectoryExisting(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - home directory permissions - existing home directories%"]
	name="File Permissions: Existing Home Directory Permissions"
	risk_description="User home directories are commonly used by the associated use to store their own files, including potential user sensitive data. Home directories on the host have been identified with unsuitable permissions which could allow malicious users to steal or modify data, or to gain other users system privileges. Disabling read and execute access for users, who are not members of the same group, allows for appropriate use of discretionary access control by each user.\n\nThe following home directories have inappropriate permissions and/or ownership:\n\n#######"
	recommendation="Review the permissions/ownership of each home directory. The following command is recommended to apply a suitable configuration:\n\nchmod 750 <Home Directory>\n\nNote:The following script may be used to automate this process:\n\nNEW_PERMS=750 lsuser -c ALL | grep -v ^#name | cut -f1 -d- | while read NAME; do\nif [ `lsuser -f $NAME | grep id | cut -f2 -d=` -ge 200 ]; then\nHOME=`lsuser -a home $NAME | cut -f 2 -d =`\necho Changing $NAME homedir $HOME\nchmod $NEW_PERMS $HOME\nfi\ndone"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsHomeDirectoryNew(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - home directory permissions - new home directories%"]
	name="File Permissions: New Home Directory Permissions"
	risk_description="The hosts current configuration results in newly created user home directories being granted with over-permissive permissions. This would result in any new users home directory and contents being accessible to other users, which could lead to the theft or modification of data, or the acquisition of the users system privileges.\n\nThe setting for the default permissions on home directories is controlled within the /usr/lib/security/mkuser.sys file."
	recommendation="Suitable permissions (i.e. 750) can be enforced on newly created home directories by modifying the /usr/lib/security/mkuser.sys file using a text editor to alter the mkdir $1 entry with mkdir $1 && chmod u=rwx,g=rx,o= $1\str()"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids PermissionsRootPathWorldGroupWriteableDirectory(CompliancePlugin):
	plugin_ids=["%Permissions and Ownership - world/group writable directory in root PATH%"]
	name="File Permissions: World/Group Writable Directory in root PATH"
	risk_description="The current PATH environment variable value for the \"root\" user contains directories with overly permissive permissions. There should not be group or world writable directories in the root users executable path as it could allow an attacker/malicious used to gain super user access by forcing an administrator operating as \"root\" to execute a malicious program.\n\nThe following PATH value was seen to be set for the \"root\" user:\nPATH=##########################\n\nThe following directories are seen to have unsuitable permissions set:\n"
	recommendation="Review the group or world writable directories in roots PATH. Manually change permissions on any affected directories:\n\nTo remove group writable access: chmod g-w <dir name>\nTo remove world writable access: chmod o-w <dir name>\nTo remove both group and world writable access: chmod go-w <dir name>\nTo change the owner of a directory: chown <owner> <dir name>"


	####Miscellaneous Config
	####Section 4.12

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MiscellaneousConfigAuthUsersAtAllow(CompliancePlugin):
	plugin_ids=["%Miscellaneous Config - authorized users in at.allow - adm%","%Miscellaneous Config - authorized users in at.allow - sys%","%Miscellaneous Config - authorized users in at.allow - at.allow contains adm","%Miscellaneous Config - authorized users in at.allow - at.allow contains sys"]
	name="Miscellaneous Configuration: Authorised Users in at.allow"
	risk_description="The /var/adm/cron/at.allow file can be used to define which users on the system are able to schedule jobs via the \"at\" program. Currently the host does not suitably restrict access to \"at\" to a chosen list of users, potentially allowing all users to schedule jobs (which could facilitate privilege escalation or information disclosure)."
	recommendation="Add the recommended system users to the at.allow list:\n\necho adm >>/var/adm/cron/at.allow\necho sys >> /var/adm/cron/at.allow\n\nOther users which require permissions to use the \"at\" scheduler can also be added to this file in the same manner."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MiscellaneousConfigAuthUsersAtAllow(CompliancePlugin):
	plugin_ids=["%Miscellaneous Config - authorized users in cron.allow - adm%","%Miscellaneous Config - authorized users in cron.allow - sys%","%Miscellaneous Config - authorized users in cron.allow - cron.allow contains adm","%Miscellaneous Config - authorized users in cron.allow - cron.allow contains sys","%Miscellaneous Config - authorized users in cron.allow - cron.allow contains no other entries besides sys and adm"]
	name="Miscellaneous Configuration: Authorised Users in cron.allow"
	risk_description="The /var/adm/cron/cron.allow file can be used to define which users on the system are able to schedule jobs via the \"cron\" program. Currently the host does not suitably restrict access to \"cron\" to a chosen list of users, potentially allowing all users to schedule jobs (which could facilitate privilege escalation or information disclosure)."
	recommendation="Add the recommended system users to the cron.allow list:\n\necho adm >>/var/adm/cron/cron.allow\necho sys >> /var/adm/cron/cron.allow\n\nOther users which require permissions to use the \"cron\" scheduler can also be added to this file in the same manner."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MiscellaneousConfigUnlockedAccountsPassword(CompliancePlugin):
	plugin_ids=["%Miscellaneous Config - all unlocked accounts must have a password%","%Miscellaneous Config - all unlocked accounts must have a password%"]
	name="Miscellaneous Configuration: Unlocked Account Must Have A Password"
	risk_description="User accounts were identified on the host without a password set using the pwdck utility. Whilst it may not be immediately possible to access the host using each account (e.g. via SSH for example) due to access restrictions, an account with a blank password could permit multiple users to utilise it without proper authentication and would leave a reduced audit trail. In the event of malicious activity it would increase the difficulty of attributing this to a specific user.\n\nThe following user accounts were seen to be set in this manner:\n###################"
	recommendation="Check for empty passwords using the following command:\n\npwdck -n ALL\n\nIf it yields output, set up a suitable password on each affected account:\npasswd <username>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MiscellaneousConfigUnnecessaryUsersGroups(CompliancePlugin):
	plugin_ids=["%Miscellaneous Config - unnecessary user and group removal - /etc/group - printq%","%Miscellaneous Config - unnecessary user and group removal - /etc/group - uucp%","%Miscellaneous Config - unnecessary user and group removal - /etc/passwd - lpd%","%Miscellaneous Config - unnecessary user and group removal - /etc/passwd - nuucp%","%Miscellaneous Config - unnecessary user and group removal - /etc/passwd - uucp%"]
	name="Miscellaneous Configuration: Unnecessary User/Group Removal"
	risk_description="Accounts and groups relating to default administrative users are configured on the host. These are typically targeted by attackers in an attempt to gain unauthorised access to a host as the accounts are generic across default deployments. Removing them is seen to further enhance the security of the host. Common users include uucp, nuucp and lpd and common groups include printq and uucp."
	recommendation="If possible/not required, remove the uucp, nuucp, lpd, and printq user accounts and their respective groups from the host. It should be noted that this list should not be considered exhaustive and other users and groups can be added to this list if required using the \"rmuser\" and \"rmgroups\" commands."

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)


	# New plugin_ids MiscellaneousConfigFTPUmask(CompliancePlugin):
	plugin_ids=["%Miscellaneous Config - ftp umask%"]
	name="Miscellaneous Configuration: FTP umask"
	risk_description="The umask of the FTP service configured in /etc/inetd.conf is recommended to be set in a manner to prevent the creation of world-writable files. This is typically recommended to be implemented by setting the umask to at least 027, only allowing the file owner to write its contents. There are a number of reasons this umask value may differ, particularly if an FTP server is intended to be used for anonymous or unrestricted file transfer. The current value is not set in line with the recommended minimum umask value."
	recommendation="Set the umask value for FTP to at least 027 (or in line with the service requirements). The following command can be used to implement this configuration:\n\nchsubserver -c -v ftp -p tcp ftpd -l -u027"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
