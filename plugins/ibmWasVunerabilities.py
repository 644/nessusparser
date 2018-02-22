from plugins import genFile

def gen(cb):
	plugin_ids=['IBM WebSphere Application Server 6.1%']
	name="IBM WebSphere Application Server"
	description="Several hosts present IBM WebSphere Application Server (WAS) services which are running on a dated version. As updates are made available to address both functional and security issues, such deployments are seen to present a risk."
	risk_description="The versions of the IBM WAS web server software running services on a number of hosts has been superseded by more recent releases/Fix Packs. Each Fix Pack addressed security vulnerabilities of varying risk/impact. The use of older software versions leaves the services, their traffic and the underlying hosts vulnerable to exploitation, with issues threatening the security of service traffic, service availability (through possible denial-of-service attacks), authentication bypass and code execution vulnerabilities which threaten the underlying host."
	recommendation="Ensure that each WAS instance is kept suitably updated, in line with the agreed patching policy."
	notes=str()
