from plugins import genFile

def gen(cb):
	name="VMware ESX/ESXi"
	plugin_ids=['VMware ESX%','VMware ESXi%','ESXi 5.%', 'ESX%']
	description="The VMWare vSphere ESX/ESXi hypervisor software solutions provides functionality with which organisations are able to deploy a multitude of virtual assets, including servers and networking devices. As these hypervisors are typically used to host the majority of infrastructure assets due to the flexibility a virtual environment can offer, vulnerabilities within the deployed ESX/ESXi software versions could have a potentially critical impact on an environment if exploited."
	risk_description="Issues are known to be associated with the identified deployments of the VMware ESX/ESXi software running on hosts throughout the assessed network. These issues range from information disclosure issues to buffer overflow vulnerabilities with publicly available exploits. Each instance of an issue could provide an attacker with useful information that could benefit further attacks or, in the more severe cases, could be used to remotely compromise a host with SYSTEM/root level privileges.\n\nIt should be noted that a number of these issues require that specific functionality be enabled and utilised by the software (e.g. Network File Copy or virtual iSCSI devices) or that the attacker has access to a valid user account on the deployment, reducing the likelihood of such issues being exploited."
	recommendation="Update each ESX/ESXi deployment to the most recent supported release for its current branch."
	notes="<url>http://www.vmware.com/security/advisories.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
