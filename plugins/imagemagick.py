from plugins import genFile

def gen(cb):
	plugin_ids=['ImageMagick <%']
	name="ImageMagick"
	description="Hosts have versions of the ImageMagick software installed that are affected by multiple vulnerabilities. Exploitation of such issues typically requires a user to be tricked into accessing a malicious resource and could enable the remote compromise of a host."
	risk_description="Authenticated assessment has identified that the version of ImageMagick installed on a number of hosts predates more recent releases. Such installations are affected by a number of denial of service, buffer overflow and arbitrary code execution vulnerabilities which can be leveraged through tricking a user into opening crafted files. The more severe of these issues could result in the remote compromise of the underlying host, potentially introducing further avenues of attack against the host and other assets."
	recommendation="Upgrade the ImageMagick software to the most recent release or remove it from the system if not required. Vulnerable versions may have to be removed from the system."
	notes=str()

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
