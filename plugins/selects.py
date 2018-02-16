import sqlite3

def pluginName(nlist, cb):
	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	name_like = ' OR '.join("'" + n + "'" for n in nlist)
	c.execute(f"select reports.host_ip from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_name LIKE {name_like} AND reports.report_name = ?", [cb])
	all_rows = c.fetchall()
	conn.close()
	return all_rows

def pluginId(ilist, cb):
	conn = sqlite3.connect('./reports.db')
	c = conn.cursor()
	id_like = ' OR '.join("'" + str(i) + "'" for i in ilist)
	c.execute(f"select reports.host_ip,reportitems.plugin_name from reportitems INNER JOIN reports ON reports.report_id = reportitems.report_id WHERE reportitems.plugin_id = {id_like} AND reports.report_name = ?", [cb])
	all_rows = c.fetchall()
	conn.close()
	return all_rows
