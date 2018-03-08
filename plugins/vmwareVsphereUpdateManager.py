from plugins import genFile

def gen(cb):
	appendices = []

	name="VMware vSphere Update Manager"
	plugin_ids=['VMware vSphere Update Manager Java Vulnerability (VMSA-2015-0003)']
	description="VMware hypervisor software provides functionality with which organisations are able to deploy a multitude of virtual assets, including servers and networking devices. As these hypervisors are typically used to host the majority of infrastructure assets due to the flexibility a virtual environment can offer, vulnerabilities within the deployed VMware software versions could have a potentially critical impact on an environment if exploited. The vSphere Update Manager software is used to ensure that vSphere software remains suitable updated. Deployments of this softwareee were found to be running versions affected with known issues."
	risk_description="The versions of the VMware vSphere (formerly vCenter) Update Manager software installed on a number of hosts has been superseded by more recent updates. Known and common issues affecting such deployments include those attributed to bundled Java Runtime Environments (JREs), including a known TLS/SSL man-in-the-middle attack. Exploiting such issues successfully would grant an attacker to intercept and manipulate Update Manager traffic, which could reveal sensitive information."
	recommendation="Apply any outstanding updates for this software and ensure each deployment remains updated in line with vendor releases."
	notes="<url>http://www.vmware.com/security/advisories/VMSA-2015-0003.html</url>"

	ap = genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
	if not ap is None:
		appendices += ap



	if appendices:
		return appendices