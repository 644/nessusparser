from plugins import genFile

def gen(cb):
	plugin_ids=['Outdated Oracle GlassFish'] ## wasn't here originally
	name="Outdated Oracle GlassFish"
	description="A number of hosts have been found to be running an outdated instance of the Oracle GlassFish software. GlassFish is the reference implementation of Java EE and is used to host a variety of Java-based web applications."
	risk_description="The installation of Oracle GlassFish on each of the systems listed below has been found to be out of date. As such, they are known to be vulnerable to a number of security issues, the severity of which range from information disclosure through to remote code execution via buffer overflow."
	recommendation="It is recommended that each affected GlassFish installation be updated to the most recent avaialable stable version."
	notes="<url>https://glassfish.java.net/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
