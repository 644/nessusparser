from plugins import selects

def genr(cb, plugin_ids, name, description, risk_description, recommendation, notes):
	if isinstance(plugin_ids[0], int):
		all_rows = selects.pluginId(plugin_ids, cb)
	else:
		all_rows = selects.pluginName(plugin_ids, cb)

	all_rows = [*{*all_rows}]
	
	if len(all_rows) > 0:
		with open('./' + cb + '.txt', "a") as t_file:
			t_file.write(name + '\n' + description + '\n' + risk_description + '\n' + recommendation + '\n' + notes + '\nAffected hosts:\n')
			[ t_file.write(str(append_line[0] + '\n')) for append_line in all_rows ]
			t_file.write('\n\n\n') 
