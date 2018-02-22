from plugins import genFile

def gen(cb):
	include_strings=["  Server banner","  Installed version"]
	plugin_ids=['MiniUPnP < 1.%']
	name="MiniUPnP 1.x Deployments"
	description="Services running on MiniUPnP versions in the 1.x major release were identified on the network. Used for enabling connectivity for various network clients/services behind NAT'd connections, the software versions on services identified appear to be dated."
	risk_description="Banners retrieved from MiniUPnP services have identified them to be running older releases of MiniUPnP 1.x which are associated with known vulnerabilities.\n\nIssues affecting such releases have included buffer overflows leading to code execution or denial of service through service crashes and attacks which can be used to invoke client-side scripts on connecting client devices. Leveraging code execution attacks would result in the remote compromise of the underlying host."
	recommendation="Upgrade the MiniUPnP version to the most recent supported release. For deployments which are implemented as part of third-party software/device firmware, contact the vendor to identify if more recent releases are available to address this issue."
	notes="<url>http://miniupnp.free.fr/files/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
