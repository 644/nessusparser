#from ereplugin import *
#import re

#def sort_advisory(x,y):
	#if x[1] > y[1]:
		#return 1
	#elif y[1] > x[1]:
		#return -1
	#else:
		#return 0

#class EREPlugin(Plugin):

	#type=Type.PATCH_MANAGEMENT
	#impact=Impact.HIGH
	#risk=Risk.HIGH
	#fix_effort=FixEffort.MEDIUM
	#likelihood=Likelihood.MEDIUM
	#cvss=None

	#name = "AIX 6.1 Patching"
	#description="Updates to address security and functionality issues are regularly released for supported AIX Unix distributions. Not applying these updates to a host leaves it vulnerable to any problems addressed by the update. The severity of the issues addressed varies between updates, with the most severe potentially leading to a full compromise of the host."
	#risk_description="By running authenticated local vulnerability assessments against hosts running AIX 6.1, it was possible to identify missing security updates. These updates/APARs address a variety of issues affecting AIX deployments and their installed software. Depending on the installed versions of third-party software and AIX components, each installation can be left vulnerable to unauthenticated, remote denial-of-service attacks, code execution attacks through overflows, and information disclosure. Additionally, authenticated access to each host would provide a local, low-privileged user with opportunities to elevate their privileges and gain complete control of the underlying host."
	#recommendation="The appropriate interim fixes/patches/APARs relating to the issues listed in the Affected Components section should be applied to each affected host. The patching policy surrounding AIX deployments should also be reviewed so that similar issues that arise in future are identified and included within updates to the hosts.\n\nIt should be noted that a subscription is required to obtain the relevant fixes for these issues."
	#affected_components=str()
	#notes=str()


	#def run_plugin(self, scan_ids, severity):


		#host_results=self.store.find(Result,(Result.plugin_name.like(u"Authenticated Check : OS Name and Installed Package Enumeration") & Result.plugin_output.like(u"%The remote AIX system is : AIX 6.1 %") & Result.scan_id.is_in(scan_ids)))

		#query_hosts=[]
		#if host_results.count() >0:
			#for host_result in host_results.order_by(Result.host): #### this order by is likely to cause issues later when different subnets turn up, inet_aton will be needed
				#query_hosts.append(host_result.host)

		#results=self.store.find(Result,( ( Result.plugin_name.like(u"AIX % Advisory :%") | Result.plugin_name.like(u"AIX 6.1 TL%") ) & Result.scan_id.is_in(scan_ids) & Result.host.is_in(query_hosts)))

		#result_dict={}
		#if results.count() > 0:
			#self.add=True

			#for result in results:

				#if self.cvss == None or result.cvss_base_score > self.cvss:
					#self.cvss = result.cvss_base_score
				##print result.plugin_name
				#if "openssl" in result.plugin_name:
					#regex = re.compile('openssl_advisory\d+.asc')
				#elif "openssh" in result.plugin_name:
					#regex = re.compile('openssh_advisory\d+.asc')
				#elif "bos" in result.plugin_name:
					#regex = re.compile('U\d\d\d+')
					##Want to pull package name out.
				#else:
					#regex = re.compile('IV\d\d\d+')
					#####Need match all?
				#match = regex.search(result.plugin_name)
		                #advisory = match.group()
				#plugin_name = result.plugin_name

				#plugin_key = plugin_name,advisory

				#if plugin_key in result_dict.keys():
					#result_dict[plugin_key].append(result.host_identifier)
				#else:
					#result_dict[plugin_key]=[result.host_identifier]
				#self.store.remove(result)

		#for key,key2 in  sorted(result_dict.keys(), sort_advisory):

			#self.affected_components+="<bold_italic>{0}</bold_italic>\n".format(key.split(": ",1)[1])

			
			#for affected_component in sorted(result_dict[key,key2],sort_ip_port):
				#self.affected_components+=affected_component+"\n"
			#self.affected_components+="\n"
			
			#if "openssl" in key2:
				#self.notes+="<url>http://aix.software.ibm.com/aix/efixes/security/{0}</url>\n".format(key2.lower().strip())
			#elif "openssh" in key2:
				#self.notes+="<url>http://aix.software.ibm.com/aix/efixes/security/{0}</url>\n".format(key2.lower().strip())
			#elif "IV" in key2:
				#self.notes+="<url>http://www-01.ibm.com/support/docview.wss?uid=isg1{0}</url>\n".format(key2.upper().strip())
