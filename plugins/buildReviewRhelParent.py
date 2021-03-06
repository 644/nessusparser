from plugins import genParent

def gen(cb):
	appendices = []

	plugin_ids=["%Ensure no duplicate group names exist%"]
	plugin_ids+=["%Ensure no duplicate user names exist%"]
	plugin_ids+=["%Ensure no duplicate GIDs exist%"]
	plugin_ids+=["%Ensure no duplicate UIDs exist%"]
	plugin_ids+=["%Ensure all groups in /etc/passwd exist in /etc/group%"]
	plugin_ids+=["%Ensure no users have .rhosts files%"]
	plugin_ids+=["%Ensure users .netrc Files are not group or world accessible%"]
	plugin_ids+=["%Ensure no users have .netrc files%"]
	plugin_ids+=["%Ensure no users have .forward files%"]
	plugin_ids+=["%Ensure users dot files are not group or world writable%"]
	plugin_ids+=["%Ensure users own their home directories%"]
	plugin_ids+=["%Ensure users home directories permissions are 750 or more restrictive%"]
	plugin_ids+=["%Ensure all users home directories exist%"]
	plugin_ids+=["%Ensure root PATH Integrity%"]
	plugin_ids+=["%Ensure root is the only UID 0 account%"]
	plugin_ids+=["%Ensure no legacy + entries exist in /etc/group%"]
	plugin_ids+=["%Ensure no legacy + entries exist in /etc/shadow%"]
	plugin_ids+=["%Ensure no legacy + entries exist in /etc/passwd%"]
	plugin_ids+=["%Ensure password fields are not empty%"]
	plugin_ids+=["%Audit SGID executables%"]
	plugin_ids+=["%Audit SUID executables%"]
	plugin_ids+=["%Ensure no ungrouped files or directories exist%"]
	plugin_ids+=["%Ensure no unowned files or directories exist%"]
	plugin_ids+=["%Ensure no world writable files exist%"]
	plugin_ids+=["%Ensure permissions on /etc/gshadow- are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/group- are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/shadow- are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/passwd- are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/gshadow are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/group are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/shadow are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/passwd are configured%"]
	plugin_ids+=["%Ensure access to the su command is restricted - wheel group contains root%"]
	plugin_ids+=["%Ensure access to the su command is restricted - pam_wheel.so%"]
	plugin_ids+=["%Ensure root login is restricted to system console%"]
	plugin_ids+=["%Ensure default user umask is 027 or more restrictive - /etc/profile%"]
	plugin_ids+=["%Ensure default user umask is 027 or more restrictive - /etc/bashrc%"]
	plugin_ids+=["%Ensure default group for the root account is GID 0%"]
	plugin_ids+=["%Ensure system accounts are non-login%"]
	plugin_ids+=["%Ensure inactive password lock is 30 days or less%"]
	plugin_ids+=["%Ensure password expiration warning days is 7 or more%"]
	plugin_ids+=["%Ensure minimum days between password changes is 7 or more%"]
	plugin_ids+=["%Ensure password expiration is 90 days or less%"]
	plugin_ids+=["%Ensure password hashing algorithm is SHA-512 - password-auth%"]
	plugin_ids+=["%Ensure password hashing algorithm is SHA-512 - system-auth%"]
	plugin_ids+=["%Ensure password reuse is limited - password-auth%"]
	plugin_ids+=["%Ensure password reuse is limited - system-auth%"]
	plugin_ids+=["%Lockout for failed password attempts - password-auth auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900%"]
	plugin_ids+=["%Lockout for failed password attempts - password-auth auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900%"]
	plugin_ids+=["%Lockout for failed password attempts - password-auth auth [success=1 default=bad] pam_unix.so%"]
	plugin_ids+=["%Lockout for failed password attempts - password-auth auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900%"]
	plugin_ids+=["%Lockout for failed password attempts - system-auth auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900%"]
	plugin_ids+=["%Lockout for failed password attempts - system-auth auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900%"]
	plugin_ids+=["%Lockout for failed password attempts - system-auth auth [success=1 default=bad] pam_unix.so%"]
	plugin_ids+=["%Lockout for failed password attempts - system-auth auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900%"]
	plugin_ids+=["%Ensure password creation requirements are configured - lcredit%"]
	plugin_ids+=["%Ensure password creation requirements are configured - ocredit%"]
	plugin_ids+=["%Ensure password creation requirements are configured - ucredit%"]
	plugin_ids+=["%Ensure password creation requirements are configured - dcredit%"]
	plugin_ids+=["%Ensure password creation requirements are configured - minlen%"]
	plugin_ids+=["%Ensure password creation requirements are configured - system-auth retry=3%"]
	plugin_ids+=["%Ensure password creation requirements are configured - password-auth retry=3%"]
	plugin_ids+=["%Ensure password creation requirements are configured - system-auth try_first_pass%"]
	plugin_ids+=["%Ensure password creation requirements are configured - password-auth try_first_pass%"]
	plugin_ids+=["%Ensure SSH warning banner is configured%"]
	plugin_ids+=["%Ensure SSH access is limited%"]
	plugin_ids+=["%Ensure SSH LoginGraceTime is set to one minute or less%"]
	plugin_ids+=["%Ensure SSH Idle Timeout Interval is configured - ClientAliveCountMax%"]
	plugin_ids+=["%Ensure SSH Idle Timeout Interval is configured - ClientAliveInterval%"]
	plugin_ids+=["%Ensure only approved MAC algorithms are used%"]
	plugin_ids+=["%Ensure only approved ciphers are used%"]
	plugin_ids+=["%Ensure SSH PermitUserEnvironment is disabled%"]
	plugin_ids+=["%Ensure SSH PermitEmptyPasswords is disabled%"]
	plugin_ids+=["%Ensure SSH root login is disabled%"]
	plugin_ids+=["%Ensure SSH HostbasedAuthentication is disabled%"]
	plugin_ids+=["%Ensure SSH IgnoreRhosts is enabled%"]
	plugin_ids+=["%Ensure SSH MaxAuthTries is set to 4 or less%"]
	plugin_ids+=["%Ensure SSH X11 forwarding is disabled%"]
	plugin_ids+=["%Ensure SSH LogLevel is set to INFO%"]
	plugin_ids+=["%Ensure SSH Protocol is set to 2%"]
	plugin_ids+=["%Ensure permissions on /etc/ssh/sshd_config are configured%"]
	plugin_ids+=["%Ensure at/cron is restricted to authorized users - at.deny%"]
	plugin_ids+=["%Ensure at/cron is restricted to authorized users - at.allow%"]
	plugin_ids+=["%Ensure at/cron is restricted to authorized users - cron.deny%"]
	plugin_ids+=["%Ensure at/cron is restricted to authorized users - cron.allow%"]
	plugin_ids+=["%Ensure permissions on /etc/cron.d are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/cron.monthly are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/cron.weekly are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/cron.daily are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/cron.hourly are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/crontab are configured%"]
	plugin_ids+=["%Ensure cron daemon is enabled%"]
	plugin_ids+=["%Ensure logrotate is configured%"]
	plugin_ids+=["%Ensure permissions on all logfiles are configured%"]
	plugin_ids+=["%Ensure rsyslog or syslog-ng is installed%"]
	plugin_ids+=["%Ensure remote rsyslog messages are only accepted on designated log hosts. - InputTCPServerRun 514%"]
	plugin_ids+=["%Ensure remote rsyslog messages are only accepted on designated log hosts. - imtcp.so%"]
	plugin_ids+=["%Ensure rsyslog is configured to send logs to a remote log host%"]
	plugin_ids+=["%Ensure rsyslog default file permissions configured%"]
	plugin_ids+=["%Ensure logging is configured%"]
	plugin_ids+=["%Ensure rsyslog Service is enabled%"]
	plugin_ids+=["%Ensure wireless interfaces are disabled%"]
	plugin_ids+=["%Ensure firewall rules exist for all open ports%"]
	plugin_ids+=["%Ensure outbound and established connections are configured%"]
	plugin_ids+=["%Ensure loopback traffic is configured%"]
	plugin_ids+=["%Ensure default deny firewall policy - Chain OUTPUT%"]
	plugin_ids+=["%Ensure default deny firewall policy - Chain FORWARD%"]
	plugin_ids+=["%Ensure default deny firewall policy - Chain INPUT%"]
	plugin_ids+=["%Ensure iptables is installed%"]
	plugin_ids+=["%Ensure TIPC is disabled%"]
	plugin_ids+=["%Ensure RDS is disabled%"]
	plugin_ids+=["%Ensure SCTP is disabled%"]
	plugin_ids+=["%Ensure DCCP is disabled%"]
	plugin_ids+=["%Ensure permissions on /etc/hosts.deny are 644%"]
	plugin_ids+=["%Ensure permissions on /etc/hosts.allow are configured%"]
	plugin_ids+=["%Ensure /etc/hosts.deny is configured%"]
	plugin_ids+=["%Ensure /etc/hosts.allow is configured%"]
	plugin_ids+=["%Ensure TCP Wrappers is installed%"]
	plugin_ids+=["%Ensure IPv6 is disabled%"]
	plugin_ids+=["%Ensure IPv6 redirects are not accepted - net.ipv6.conf.all.accept_redirects = 0%"]
	plugin_ids+=["%Ensure IPv6 redirects are not accepted - net.ipv6.conf.default.accept_redirects = 0%"]
	plugin_ids+=["%Ensure IPv6 router advertisements are not accepted - net.ipv6.conf.default.accept_ra = 0%"]
	plugin_ids+=["%Ensure IPv6 router advertisements are not accepted - net.ipv6.conf.all.accept_ra = 0%"]
	plugin_ids+=["%Ensure TCP SYN Cookies is enabled%"]
	plugin_ids+=["%Ensure Reverse Path Filtering is enabled - net.ipv4.conf.all.rp_filter = 1%"]
	plugin_ids+=["%Ensure Reverse Path Filtering is enabled - net.ipv4.conf.default.rp_filter = 1%"]
	plugin_ids+=["%Ensure bogus ICMP responses are ignored%"]
	plugin_ids+=["%Ensure broadcast ICMP requests are ignored%"]
	plugin_ids+=["%Ensure suspicious packets are logged - net.ipv4.conf.default.log_martians = 1%"]
	plugin_ids+=["%Ensure suspicious packets are logged - net.ipv4.conf.all.log_martians = 1%"]
	plugin_ids+=["%Ensure secure ICMP redirects are not accepted - net.ipv4.conf.all.secure_redirects = 0%"]
	plugin_ids+=["%Ensure secure ICMP redirects are not accepted - net.ipv4.conf.default.secure_redirects = 0%"]
	plugin_ids+=["%Ensure ICMP redirects are not accepted - net.ipv4.conf.default.accept_redirects = 0%"]
	plugin_ids+=["%Ensure ICMP redirects are not accepted - net.ipv4.conf.all.accept_redirects = 0%"]
	plugin_ids+=["%Ensure source routed packets are not accepted - net.ipv4.conf.all.accept_source_route = 0%"]
	plugin_ids+=["%Ensure source routed packets are not accepted - net.ipv4.conf.default.accept_source_route = 0%"]
	plugin_ids+=["%Ensure packet redirect sending is disabled - net.ipv4.conf.default.send_redirects = 0%"]
	plugin_ids+=["%Ensure packet redirect sending is disabled - net.ipv4.conf.all.send_redirects = 0%"]
	plugin_ids+=["%Ensure LDAP client is not installed%"]
	plugin_ids+=["%Ensure telnet client is not installed%"]
	plugin_ids+=["%Ensure talk client is not installed%"]
	plugin_ids+=["%Ensure rsh client is not installed%"]
	plugin_ids+=["%Ensure NIS Client is not installed%"]
	plugin_ids+=["%Ensure rsync service is not enabled%"]
	plugin_ids+=["%Ensure tftp server is not enabled%"]
	plugin_ids+=["%Ensure telnet server is not enabled%"]
	plugin_ids+=["%Ensure talk server is not enabled%"]
	plugin_ids+=["%Ensure rsh server is not enabled - rsh%"]
	plugin_ids+=["%Ensure rsh server is not enabled - rlogin%"]
	plugin_ids+=["%Ensure rsh server is not enabled - rexec%"]
	plugin_ids+=["%Ensure NIS Server is not enabled%"]
	plugin_ids+=["%Ensure mail transfer agent is configured for local-only mode%"]
	plugin_ids+=["%Ensure SNMP Server is not enabled%"]
	plugin_ids+=["%Ensure HTTP Proxy Server is not enabled%"]
	plugin_ids+=["%Ensure Samba is not enabled%"]
	plugin_ids+=["%Ensure IMAP and POP3 server is not enabled%"]
	plugin_ids+=["%Ensure HTTP server is not enabled%"]
	plugin_ids+=["%Ensure FTP Server is not enabled%"]
	plugin_ids+=["%Ensure DNS Server is not enabled%"]
	plugin_ids+=["%Ensure NFS and RPC are not enabled - RPC%"]
	plugin_ids+=["%Ensure NFS and RPC are not enabled - NFS%"]
	plugin_ids+=["%Ensure LDAP server is not enabled%"]
	plugin_ids+=["%Ensure DHCP Server is not enabled%"]
	plugin_ids+=["%Ensure CUPS is not enabled%"]
	plugin_ids+=["%Ensure Avahi Server is not enabled%"]
	plugin_ids+=["%Ensure X Window System is not installed%"]
	plugin_ids+=["%Ensure chrony is configured - OPTIONS%"]
	plugin_ids+=["%Ensure chrony is configured - NTP server%"]
	plugin_ids+=["%Ensure ntp is configured - OPTIONS or ExecStart -u ntp:ntp%"]
	plugin_ids+=["%Ensure ntp is configured - NTP Server%"]
	plugin_ids+=["%Ensure ntp is configured - restrict -6%"]
	plugin_ids+=["%Ensure ntp is configured - restrict -4%"]
	plugin_ids+=["%Ensure time synchronization is in use%"]
	plugin_ids+=["%Ensure xinetd is not enabled%"]
	plugin_ids+=["%Ensure tftp server is not enabled%"]
	plugin_ids+=["%Ensure time services are not enabled - time-dgram%"]
	plugin_ids+=["%Ensure time services are not enabled - time-stream%"]
	plugin_ids+=["%Ensure echo services are not enabled - echo-dgram%"]
	plugin_ids+=["%Ensure echo services are not enabled - echo-stream%"]
	plugin_ids+=["%Ensure discard services are not enabled - discard-dgram%"]
	plugin_ids+=["%Ensure discard services are not enabled - discard-stream%"]
	plugin_ids+=["%Ensure daytime services are not enabled - daytime-dgram%"]
	plugin_ids+=["%Ensure daytime services are not enabled - daytime-stream%"]
	plugin_ids+=["%Ensure chargen services are not enabled - chargen-dgram%"]
	plugin_ids+=["%Ensure chargen services are not enabled - chargen-stream%"]
	plugin_ids+=["%Ensure updates, patches, and additional security software are installed%"]
	plugin_ids+=["%Ensure GDM login banner is configured - not installed%"]
	plugin_ids+=["%Ensure permissions on /etc/issue.net are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/issue are configured%"]
	plugin_ids+=["%Ensure permissions on /etc/motd are configured%"]
	plugin_ids+=["%Ensure remote login warning banner is configured properly%"]
	plugin_ids+=["%Ensure local login warning banner is configured properly%"]
	plugin_ids+=["%Ensure message of the day is configured properly%"]
	plugin_ids+=["%Ensure prelink is disabled%"]
	plugin_ids+=["%Ensure address space layout randomization (ASLR) is enabled%"]
	plugin_ids+=["%Ensure XD/NX support is enabled%"]
	plugin_ids+=["%Ensure core dumps are restricted - sysctl%"]
	plugin_ids+=["%Ensure core dumps are restricted - limits.conf%"]
	plugin_ids+=["%Ensure authentication required for single user mode - emergency.service%"]
	plugin_ids+=["%Ensure authentication required for single user mode - rescue.service%"]
	plugin_ids+=["%Ensure bootloader password is set - password_pbkdf2%"]
	plugin_ids+=["%Ensure bootloader password is set - set superusers%"]
	plugin_ids+=["%Ensure permissions on bootloader config are configured%"]
	plugin_ids+=["%Ensure filesystem integrity is regularly checked%"]
	plugin_ids+=["%Ensure AIDE is installed%"]
	plugin_ids+=["%Ensure Red Hat Network or Subscription Manager connection is configured%"]
	plugin_ids+=["%Ensure GPG keys are configured%"]
	plugin_ids+=["%Ensure gpgcheck is globally activated%"]
	plugin_ids+=["%Ensure package manager repositories are configured%"]
	plugin_ids+=["%Disable Automounting%"]
	plugin_ids+=["%Ensure sticky bit is set on all world-writable directories%"]
	plugin_ids+=["%Ensure noexec option set on /dev/shm partition%"]
	plugin_ids+=["%Ensure nosuid option set on /dev/shm partition%"]
	plugin_ids+=["%Ensure nodev option set on /dev/shm partition%"]
	plugin_ids+=["%Ensure nodev option set on /home partition%"]
	plugin_ids+=["%Ensure noexec option set on /var/tmp partition%"]
	plugin_ids+=["%Ensure nosuid option set on /var/tmp partition%"]
	plugin_ids+=["%Ensure nodev option set on /var/tmp partition%"]
	plugin_ids+=["%Ensure noexec option set on /tmp partition%"]
	plugin_ids+=["%Ensure nosuid option set on /tmp partition%"]
	plugin_ids+=["%Ensure nodev option set on /tmp partition%"]
	plugin_ids+=["%Ensure mounting of FAT filesystems is disabled%"]
	plugin_ids+=["%Ensure mounting of udf filesystems is disabled%"]
	plugin_ids+=["%Ensure mounting of squashfs filesystems is disabled%"]
	plugin_ids+=["%Ensure mounting of hfsplus filesystems is disabled%"]
	plugin_ids+=["%Ensure mounting of hfs filesystems is disabled%"]
	plugin_ids+=["%Ensure mounting of jffs2 filesystems is disabled%"]
	plugin_ids+=["%Ensure mounting of freevxfs filesystems is disabled%"]
	plugin_ids+=["%Ensure mounting of cramfs filesystems is disabled%"]

	description="The following section details the findings of a RHEL system configuration build review carried out against network connected hosts.\nThe current values set for the following settings are not seen to be in line with generic best practice guidelines (e.g. CIS). Some of these values may be set in a manner reflective of organisational policy and the risks presented by the use of such settings accepted as part of organisational policy. It is recommended that each setting be reviewed in order to ensure the host build is suitably hardened.\n<url>https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v2.1.1.pdf</url>"

	genParent.genr(cb, plugin_ids, description)
