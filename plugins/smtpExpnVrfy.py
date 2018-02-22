from plugins import genFile

def gen(cb):
	plugin_ids=[10249]
	name="Mail Server Information Disclosure (EXPN/VRFY)"
	description="It is possible to determine valid users from mail servers due to the support for specific methods."
	risk_description="The affected mail servers permit remote users to issue EXPN and VRFY commands. EXPN command can be used to find the delivery address of mail aliases, or even the full name of the recipients, and the VRFY command may be used to check the validity of an account.\n\nThis combination can help to identify user account details, potentially leaving them prone to targeted brute-force attacks or phishing."
	recommendation="For Sendmail deployments, the setting \"O PrivacyOptions=goaway\" can be added in the /etc/sendmail.cf configuration file. For other mail servers, vendor documentation will need to be consulted."
	notes="<url>http://www.ietf.org/rfc/rfc2821.txt</url>"
	notes+="\n<url>https://cvedetails.com/cve/CVE-1999-0531/</url>"

	genFile.genr(cb, plugin_ids, name, description, risk_description, recommendation, notes)
