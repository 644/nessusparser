from plugins import genFile

def gen(cb):
	name="Samba Version"
	plugin_ids=["Samba Version"] ## not here previously
	description="Samba services presented by hosts were found to be running on top of outdated versions of the software. Issues affecting such versions can compromise the confidentiality, integrity and availability of the service and underlying host. Depending on the functionality provided by a Samba service, this could provide access to sensitive data hosted on file shares or permit alterations to Domain configurations."
	risk_description="Based on the banners and responses returned by the identified Samba services, hosts are running versions of the software that are out of date and associated with known issues. Common issues identified within Samba (and addressed in more recent releases) include arbitrary remote code execution through crafted packets or traffic manipulation, denial of service, traffic manipulation/spoofing and information disclosure vulnerabilities. The more severe of these issues could lead to a compromise of the underlying host with root privileges, granting an attacker full access to the system and permitting it to used to attack other network reachable hosts."
	recommendation="Upgrade the Samba installation to the most recent, supported release.\n\nIt should be noted that Samba is often packaged into other software, such as Network Attached Storage (NAS) devices, and can not be updated directly. Upgrading the software/firmware of such devices may address these issues if suitable updates to the bundled Samba package have been applied by the vendor. Discussions with the vendor of such devices may be required in order to see the issues addressed."
	notes="<url>https://www.samba.org/samba/history/</url>"
	notes+="<url>https://wiki.samba.org/index.php/Samba_Release_Planning</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
