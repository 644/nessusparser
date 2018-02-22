from plugins import genFile

def gen(cb):
	plugin_ids=['IBM DB2 10.5 <%']
	name="IBM DB2 10.5 Deployments"
	description="Several hosts present IBM DB2 services which are running on a dated version. As updates are made available to address both functional and security issues, such deployments are seen to present a risk."
	risk_description="The versions of the IBM DB2 database software running services on a number of hosts has been superseded by more recent releases to the relevant branch (10.5). Each released update addressed security vulnerabilities of varying risk/impact. The use of older software versions leaves the services, their traffic and the underlying hosts vulnerable to exploitation, with issues threatening the security of service traffic, service availability (through possible denial-of-service attacks), authentication bypass and code execution vulnerabilities which threaten the underlying host."
	recommendation="Ensure that each DB2 instance is kept suitably updated, in line with the agreed patching policy."
	notes=str()

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
