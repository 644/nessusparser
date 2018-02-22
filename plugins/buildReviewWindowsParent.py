from plugins import genParent

def gen(cb):
	plugin_ids=["%Rename administrator account%"]
	plugin_ids+=["%Rename guest account%"]
	plugin_ids+=["%Do not allow anonymous enumeration of SAM accounts and shares%"]
	plugin_ids+=["%Admin Approval Mode for the Built-in Administrator account%"]
	plugin_ids+=["%Behavior of the Elevation Prompt for Administrators in Admin Approval Mode%"]
	plugin_ids+=["%Apply UAC restrictions to local accounts on network logons%"]
	plugin_ids+=["%Do not display last user name%"]
	plugin_ids+=["%Number of previous logons to cache%"]
	plugin_ids+=["%Require Domain Controller authentication to unlock workstation%"]
	plugin_ids+=["%Minimum session security for NTLM SSP based % servers%"]
	plugin_ids+=["%Minimum session security for NTLM SSP based % clients%"]
	plugin_ids+=["%LAPS AdmPwd GPO Extension / CSE%"]
	plugin_ids+=["%Hardened UNC Paths%"]

	description="Build Review\nThe following section details the findings of a Windows system configuration build review carried out against network connected hosts.\nThe current values set for the following settings are not seen to be in line with generic best practice guidelines (e.g. CIS). Some of these values may be set in a manner reflective of organisational policy and the risks presented by the use of such settings accepted as part of organisational policy. It is recommended that each setting be reviewed in order to ensure the host build is suitably hardened."

	genParent.genr(cb, plugin_ids, description)
