from plugins import genFile

def gen(cb):
	plugin_ids=['OpenSSL < 0.9.7%']
	name="OpenSSL 0.9.7 Services"
	description="Several hosts have been observed to present at least one services which utilises an older version of the OpenSSL 0.9.7 library to secure their traffic. Such versions are commonly superseded as a result of a number of issues affecting them, some of which can be seen to carry a significant threat to data and host security from unauthenticated attackers with access to the services or the network being used by a connecting client. Such versions are also now no longer supported, preventing them from receiving updates for any identified issues."
	risk_description="The version of the OpenSSL software seen to be utilised by at least one service on several hosts has been superseded by several more recent releases, each of which has addressed security vulnerabilities of varying risk/impact, and the overall branch (0.9.7) is no longer supported, identifying a long term threat posed by software no longer receiving security updates. The use of older software versions leaves the services, their traffic and the underlying hosts vulnerable to vulnerable to exploitation, with issues threatening the security of encrypted service traffic, service availability (through possible denial-of-service attacks), authentication bypass and code execution vulnerabilities which threaten the underlying host.\n\nIt should be noted that update backporting often takes place within software deployments such as OpenSSL for different operating systems or software deployments. This finding is reported as a result of version information regarding OpenSSL being revealed in responses from the service (e.g. in web server headers)."
	recommendation="As the deployed branch is no longer publicly supported, the OpenSSL installations should be migrated to a supported branch and kept up to date in line with future releases. If an affected service/installation is provided as part of a third party product deployment, discuss a supported upgrade path with the vendor."
	notes="<url>https://www.openssl.org/policies/releasestrat.html</url>"
	notes+="\n<url>https://www.openssl.org/news/openssl-0.9.7-notes.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
