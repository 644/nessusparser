from plugins import genFile

def gen(cb):
	plugin_ids=[32315]
	description="Hosts have been identified with Firebird Database services listening on them which are using default credentials. These services, underlying hosts and data held by services could be at risk of remote compromise."
	name="Default Credentials"
	risk_description="Deployments of Firebird on the affected hosts use default credentials to control access to the database. Knowing these, an attacker can gain administrative access to any affected applications. Whilst the tester was able to authenticate to the service, without knowing a valid Firebird Database file, they are unable to recover any data from the service."
	recommendation="Use the application\'s \'gsec\' utility to change the password for the \'SYSDBA\' account."
	notes="<url>http://www.firebirdsql.org/manual/qsg2-config.html</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
