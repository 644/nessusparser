from plugins import genFile

def gen(cb):
	plugin_ids=['Tivoli Storage Manager Server Unauthorized Access Vulnerability']
	name="Tivoli Storage Manager Server"
	description="Instances of the Tivoli Storage Manager Server were seen which are susceptible to known vulnerabilities."
	risk_description="Installations of the Tivoli Storage Manager server software were identified which are running versions affected by issues including a  vulnerability in which a local attacker is able to access data stored on the server for other users who have data stored under the same node. This is seen to impact the confidentiality and integrity of such data."
	recommendation="IBM have released a patch for this issue which should be applied to any affected installations."
	notes="<url>https://www-304.ibm.com/support/docview.wss?uid=swg21657726</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
