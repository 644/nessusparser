from plugins import genFile

def gen(cb):
	child_module = str()
	
	name="VMware vCenter Vulnerabilities"
	plugin_ids=['VMware vCenter Multiple Vulnerabilities%','VMware vCenter Server%']
	description="VMware hypervisor software provides functionality with which organisations are able to deploy a multitude of virtual assets, including servers and networking devices. As these hypervisors are typically used to host the majority of infrastructure assets due to the flexibility a virtual environment can offer, vulnerabilities within the deployed VMware software versions could have a potentially critical impact on an environment if exploited. The vCenter Server software is used to manage multiple hypervisor (ESX/ESXi instances), giving it a large amount of control over the environment."
	risk_description="The versions of VMware vCenter installed on a number of hosts have been superseded by more recent updates. Known and common issues affecting such deployments include those attributed to included OpenSSL libraries which can permit denial-of-service attacks against the service, enable man-in-the-middle attacks or permit traffic to be injected into sessions.\n\nIssues affecting the vCenter Server software also include common web application vulnerabilities, including XML external entity (XXE) injection, information disclosure and file access.\n\nBundled Apache Tomcat and Java JRE packages are also commonly found to be outdated within such builds, introducing a number of additional issues, including code execution on the underlying host, leading to its complete compromise.\n\nExploiting such issues successfully would grant an attacker access to hypervisor controls, permitting further attacks on the internal network and its virtualised assets.\n\n##################The above is very generic, although somewhat specific to some issues seen in vCenter previously. Now may be a good place to delve further into the details of the finding to justify the risk rating you have assigned, look at the actual vulns in your scan output################\n\nThe affected host/deployment version can be found in the Notes section of this finding.\n\n\###########Might want to note the MSF esx_fingerprint module for this too, which should work for vcenter.############"
	recommendation="Update each vCenter deployment to the most recent supported release for its current branch."
	notes="<url>https://my.vmware.com/en/web/vmware/info/slug/datacenter_cloud_infrastructure/vmware_vsphere/5_0</url>\n"
	notes+="<url>https://my.vmware.com/en/web/vmware/info/slug/datacenter_cloud_infrastructure/vmware_vsphere/5_5</url>\n"
	notes+="<url>https://my.vmware.com/en/web/vmware/info/slug/datacenter_cloud_infrastructure/vmware_vsphere/6_0</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes, child_module)
