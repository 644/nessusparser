from plugins import selects

def gen(cb):
	name="ActiveX Controls"

	description="Hosts have been identified with vulnerable ActiveX controls installed. Hosts would be at risk of remote compromise if a user was tricked into accessing malicious resources."

	notes="<url>https://support.microsoft.com/kb/240797</url>\n\n"

	child_module="activex_controls"
	
	all_rows = selects.pluginName(name, cb)
	all_rows = [*{*all_rows}]
	
	if len(all_rows) > 0:
		with open('./' + cb + '.txt', "a") as t_file:
			t_file.write(name + '\n' + description + '\n' + notes + '\n' + child_module + '\nAffected hosts:\n')
			[ t_file.write(str(append_line[0] + '\n')) for append_line in all_rows ]
			t_file.write('\n\n\n')
