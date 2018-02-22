from plugins import genFile

def gen(cb):
	plugin_ids=[86122]

	name="OpenSSH MaxAuthTries Bypass"
	description="The SSH server running on hosts is affected by a security bypass vulnerability that allows password brute-force attacks."
	risk_description="Each SSH server is affected by a security bypass vulnerability due to a flaw in the keyboard-interactive authentication mechanisms.\n\nThe kbdint_next_device() function in auth2-chall.c improperly restricts the processing of keyboard-interactive devices within a single connection. A remote attacker can exploit this, via a crafted keyboard-interactive 'devices' string, to bypass the normal restriction of 6 login attempts (MaxAuthTries), resulting in the ability to conduct a brute-force attack or cause a denial of service condition."
	recommendation="Upgrade to OpenSSH 7.0 or later. For assets in which the SSH software cannot be updated on its own (e.g. network devices) a firmware upgrade is expected to be required.\n\nAlternatively, this vulnerability can be mitigated on some Linux distributions by disabling the keyboard-interactive authentication method. This can be done on Linux by setting 'ChallengeResponseAuthentication' to 'no' in the /etc/ssh/sshd_config configuration file and restarting the sshd service."
	notes="<url>http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-5600</url>\n<url>http://www.openssh.com/txt/release-7.0</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
