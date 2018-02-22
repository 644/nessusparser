from plugins import genFile

def gen(cb):
	plugin_ids=['Portable OpenSSH %', 'OpenSSH X11%', 'OpenSSH%<%', 'OpenSSH 6.%', 'OpenSSH SSHFP%']
	name="OpenSSH Versions"
	description="SSH services presented by hosts were found to be running on top of outdated versions of OpenSSH and may be affected by several issues. These issues can lead to the damage of the confidentiality, integrity and availability of the service and underlying host, particularly as the SSH service is typically used to administer networking devices and non-Windows based hosts (e.g. Unix/Linux deployments)."
	risk_description="Based on the banners and responses returned by the identified SSH services, hosts are running versions of the OpenSSH software that are out of date and are therefore potentially affected by a variety of issues. Common issues identified (and addressed in more recent releases) include information disclosure vulnerabilities which can disclose private keys (leading to impersonation attacks) and buffer overflow issues resulting in denial of services as well as other issues."
	recommendation="Upgrade the OpenSSH installations to the most recent, supported release.\n\nIt should be noted that OpenSSH is often packaged into other software, such as router/switch operating systems, and can not be updated directly. Upgrading the software/firmware of such devices may address these issues if suitable updates to the bundled OpenSSH package have been applied by the vendor."
	notes="<url>http://www.openssh.com/</url>"
	notes+="\n<url>http://www.openssh.com/security.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
