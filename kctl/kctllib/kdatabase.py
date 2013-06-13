# -*- mode: python; tab-width: 4; indent-tabs-mode: t; python-indent: 4 -*-

#####
##### DATABASE STUFF
#####

import pgdb
import os
import time

from config import *
from kctllib.kparams import *
from kctllib.kexcept import *
from kctllib.ktbxsosdconfig import *
from kctllib.kiniconfig import *
from pg import escape_string

# kpython
from kout import *

class NoRow(KctlException):
	def __init__(self, err_msg):
		self.err_msg=err_msg
	def __str__(self):
		return repr(self.err_msg)

# will contain database handlers

dbs = None     # Python DB API
dbs_info = {}

# init settings for all databases
def db_init(db_port = None):
	global dbs
	global dbs_info

	# get databases connection info
	# first try ini files... 
	# then try tbxsosd files
	try:
		debug("Trying to read default .ini configuration.")
		config = KIniConfig()
		dbs_info["name"] = config.get("databases", "db.name")
		dbs_info["host"] = config.get("databases", "db.host")
		dbs_info["username"] = config.get("databases", "db.admin_username")
		dbs_info["password"] = config.get("databases", "db.admin_password")

		if not db_port:
			dbs_info["port"] = config.get("databases", "db.port")
		else:
			dbs_info["port"] = db_port
	except:
		debug("Trying to read tbxsosd configuration.")		
		import os
		config = KTbxsosdConfig(source_file = os.path.join(CONF_DIR, "tbxsosd.conf"))
		# This tells if kctl should try to login with the current username.
		kctl_curr_creds = config.get("kctl.curr_creds")
		dbs_info["name"] = config.get("db.name")
		dbs_info["host"] = config.get("db.host")

		if not db_port:
			dbs_info["port"] = config.get("db.port")
		else:
			dbs_info["port"] = db_port
				
		if str(kctl_curr_creds) == str(1):
			import pwd, os
			dbs_info["username"] = pwd.getpwuid(os.getuid())[0]
			dbs_info["password"] = config.get("db.admin_password")
		else:
			dbs_info["username"] = config.get("db.admin_username")
			dbs_info["password"] = config.get("db.admin_password")

# what can be None (connect to all databases) or a list of ids of databases to connect to
def db_conn():
	global dbs
	global dbs_info

	if dbs == None:
		debug("Connecting to database' (params %s)" % ( str(dbs_info) ))
		host = dbs_info["host"]
		if dbs_info["port"] != None and dbs_info["port"] != "":
			host = host + ":" + str(dbs_info["port"])
		dbs = pgdb.connect(host = host, database = dbs_info["name"],
						   user = dbs_info["username"], password = dbs_info["password"])
		debug("Connection successful to database '%s'" % ( dbs_info["name"] ))

# connect to all dbs (to use only for selftest
def db_conn_all():
	for id in dbs:
		db_conn()

def db_commit():
	global dbs

	if kparams_get("commit") == True:
		dbs.commit()
		debug("commited changes.")
	else:
		dbs.rollback()
		out("NOT COMMITING DATABASE CHANGES!!!")

# quote and escape sql argument
# WARNING: uses pgdb._quote() which is an internal function
def db_safestr(p):
	if not isinstance(p, basestring):
		s = str(p)
	else:
		s = p
	return str("'" + escape_string(s) + "'")

# makes query available in debugging (debugging can be on or off - see kout.py)
def db_debug_query(query):
	if kparams_get("db_debug_query") == True:
		debug("query: '" + query + "'", True) # force debugging
	else:
		debug("query: '" + query + "'")

# exec query - raise exception if error
def db_exec(query):
	global dbs
	
	db_conn()

	cur = dbs.cursor()

	try:
		cur.execute(query)
	except pgdb.DatabaseError, e:
		db_conn()
		dbs.rollback()
		raise KctlException(str(e))

	return cur.rowcount

# returns the first element of the first row - raise NoRow if no row available
def db_get_first_element(query):
	global dbs

    db_conn()

	cur = dbs.cursor()

	try:
		cur.execute(query)
	except pgdb.DatabaseError, e:
		dbs.rollback()
		raise KctlException(str(e))

	# check row count
	if cur.rowcount == None or cur.rowcount < 1:
		raise NoRow("no row returned")

	# get first row
	row = cur.fetchone()

	return row[0]

# returns the first row - raise NoRow if no row available
def db_get_first_row(query):
	global dbs
	
    db_conn()
	cur = dbs.cursor()

	try:
		cur.execute(query)
	except pgdb.DatabaseError, e:
		dbs.rollback()
		raise KctlException(str(e))

	# check row count
	if cur.rowcount == None or cur.rowcount < 1:
		raise NoRow("no row returned")

	# get first row
	row = cur.fetchone()

	return row

# returns True if any row found - false otherwise
def db_has_record(query):
	global dbs
	
    db_conn()
	cur = dbs.cursor()

	try:
		cur.execute(query)
	except pgdb.DatabaseError, e:
		dbs.rollback()
		raise KctlException(str(e))

	# check row count
	# don't rely on rowcount since it's not working will all databases (sqlite)
	if cur.fetchone() == None:
		return False

	return True

# returns list [desc, data] from the query
# desc is a list of field infos
# data if a list of rows
# ie:
# desc: TODO
# data: [ [1, 'Gaga'], [2, 'gogo'] ]
# returns [ None, None ] if no data
def db_find_list_desc_data(query):
	global dbs
	
	db_conn()
	cur = dbs.cursor()

	try:
		cur.execute(query)
	except pgdb.DatabaseError, e:
		dbs.rollback()
		raise KctlException(str(e))

	if cur.rowcount == None or cur.rowcount < 1:
		return [ None, None ]

	field_descs = []
	for row in cur.description:
		field_descs.append([row[0]])
	#field_descs = cur.description
	res = cur.fetchall()

	return [ field_descs, res ]

# returns list of hashes
# i.e. [ { 'col1' => value1, 'col2' => value2 }, { 'col1' => value3, 'col2' => value4 } ]
# returns empty list if no data
def db_get_all_dict(query):
	global dbs
	
    db_conn()
	cur = dbs.cursor()

	try:
		cur.execute(query)
	except pgdb.DatabaseError, e:
		dbs.rollback()
		raise KctlException(str(e))

	if cur.rowcount == None:
		return None

	res = []
	desc = cur.description

	while 1:
		row = cur.fetchone()
		if row == None: break
		new_row = {}
		i = 0
		for val in row:
			fieldname = desc[i][0]
			new_row[fieldname] = val
			i += 1
		res.append(new_row)

	return res

def db_get_first_dict(query):
	dicts = db_get_all_dict(query)
	if dicts == None or len(dicts) < 1:
	    return None
	return dicts[0]

# retro compat
db_find_hash = db_get_all_dict

# returns all rows from table (as an hash)
def db_get_table_all_dict(table):
	return db_get_all_dict("SELECT * FROM " + table)

# returns all rows of a table specified where the value of
# the column specified matches the value specified.
def db_get_all_dict_column(table, column, value):
	query = "SELECT * FROM " + table + " WHERE " + column + " = %s" % ( db_safestr(value) )
	res = db_get_all_dict(query)
	return res

# returns the first row of the table specified where the value of
# the column specified matches the value specified.
def db_get_first_dict_column(table, column, value):
	query = "SELECT * FROM " + table + " WHERE " + column + " = %s" % ( db_safestr(value) )
	res = db_find_hash(query)
	if res == None or len(res) < 1:
		return None
	return res[0]
# Retro compat
db_find_id_hash = db_get_first_dict_column

# returns the first row of the table specified where the value of
# the column specified matches the value specified.
def db_has_record_id(table, column, value):
	query = "SELECT * FROM " + table + " WHERE " + column + " = %s" % ( db_safestr(value) )
	db_debug_query(query)
	return db_has_record(query)

# Variant of the function above. The rows having a value that match the value
# specified are deleted. The function returns the number of rows deleted.
def db_delete_id(table, column, value):
	query = "DELETE FROM " + table + " WHERE " + column + " = %s" % ( db_safestr(value) )
	db_exec(query)

def db_update_match(table, match_column, match_value, update_column, update_value):
	query = "UPDATE " + table + " SET " + update_column + " = " + db_safestr(update_value) + \
		" WHERE " + match_column + " = " + db_safestr(match_value)
	db_exec(query)


###
### Specialised database functions. ###
###

## LOGIN

def sdb_logins_find():
	return db_get_table_all_dict("user_login")

def sdb_login_find(id):
	return db_find_id_hash("user_login", "prof_id", id)

def sdb_login_find_by_login(login):
	return db_find_id_hash("user_login", "user_name", login)

def sdb_login_delete(id):
	return db_delete_id("user_login", "prof_id", id)

def sdb_add_login(org_id, prof_id, username, password):
	query = "select add_login(%s, %s, %s, %s);" % ( db_safestr(username), db_safestr(password), db_safestr(prof_id), db_safestr(org_id) )
	db_debug_query(query)
	db_exec(query)
sdb_addlogin = sdb_add_login

# Add login seats
def sdb_add_login_seat(username, org_name, parent_org_name):
	if parent_org_name and parent_org_name != "":
		query = "select login_add_seat(%s, %s, %s);" % (db_safestr(username), db_safestr(org_name), db_safestr(parent_org_name))
	else:
		query = "select login_add_seat(%s, %s, null);" % (db_safestr(username), db_safestr(org_name))
	db_debug_query(query)
	db_exec(query)

# Check if an user has a login seat
def sdb_login_has_seat(username):
	query = "select * from login_has_seat(%s);" % (db_safestr(username))
	db_debug_query(query)	
	answer = db_get_first_dict(query)
	return answer["login_has_seat"]

# Add login slot
def sdb_add_login_slot(username, ticket):
	query = "select login_add_slot(%s, %s);" % (db_safestr(username), db_safestr(ticket))
	db_debug_query(query)
	db_exec(query)

# Check if the user has a login slot
def sdb_login_has_slot(username):
	query = "select * from login_has_slot(%s);" % (db_safestr(username))
	db_debug_query(query)
	answer = db_get_first_dict(query)
	return answer["login_has_slot"]

def sdb_login_update(old_login, new_login):
	return db_update_match("user_login", "user_name", old_login, "user_name", new_login)

def sdb_password_update(login, password):
	return db_update_match("user_login", "user_name", login, "passwd", password)

def sdb_rm_login(login):
	query = "select del_login(%s);" % ( db_safestr(login) )
	db_debug_query(query)
	db_exec(query)
sdb_rmlogin = sdb_rm_login

def sdb_ls_logins():
	query = "select * from login_view;"
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lslogin = sdb_ls_logins

def sdb_reseller_allocated_seats(org_id):
	query = "select * from get_reseller_seats_allocation(%s);" % ( db_safestr(org_id) )
	db_debug_query(query)
	return db_get_first_element(query)

def sdb_allocated_seats(org_id):
	query = "select * from get_seats_allocation(%s);" % ( db_safestr(org_id) )
	db_debug_query(query)
	return db_get_first_element(query)

def sdb_set_seats_allocation(p_org_id, org_id, number):
	query = "select set_seats_allocation(%s, %s, %s);" % ( db_safestr(p_org_id), db_safestr(org_id), db_safestr(number) )
	db_debug_query(query)
	db_exec(query)
sdb_setseatsallocation = sdb_set_seats_allocation

def sdb_ls_seats_allocation():
	query = "select * from login_seats_allocation"
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lsseatsallocation = sdb_ls_seats_allocation

def sdb_ls_login_seats():
	query = "select username, org_name, parent_org_name from login_seats_view"
	db_debug_query(query)
	return db_find_list_desc_data(query)

def sdb_ls_login_slots():
	query = "select username, token from login_slots_view"
	db_debug_query(query)
	return db_find_list_desc_data(query)

# Not testable indiviually.
def sdb_ls_seats_org(org_id):
	query = "select user_name from login_seats where org_id=%s" % ( db_safestr(org_id) )
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lsseatorg = sdb_ls_seats_org

# Not testable individually.
def sdb_free_login_seat(org_id, username):
	query = "select free_login_seat(%s, %s);" % ( db_safestr(org_id), db_safestr(username) )
	db_debug_query(query)
	db_exec(query)
sdb_freeloginseat = sdb_free_login_seat

## PROFILES AND ORGANIZATION

def sdb_get_main_org_id():
    ret = db_get_first_dict("select min(org_id) as org_id from organization")
    if ret: ret = ret['org_id']
    return ret

def sdb_profiles_find():
	return db_find_hash("SELECT * FROM profiles")

def sdb_profile_find(id):
	return db_find_id_hash("profiles", "prof_id", id)

def sdb_user_profile_valid(id):
	return db_has_record_id("user_profiles", "user_id", id)

def sdb_user_prof_id_valid(id):
	return db_has_record_id("user_profiles", "prof_id", id)

def sdb_org_kdn_exists(org_name):
	return db_has_record_id("organization", "name", org_name)
sdb_org_KDN_exists = sdb_org_kdn_exists

def sdb_org_id_exists(id):
	return db_has_record_id("organization", "org_id", id)

def sdb_get_org_by_org_id(id):
    return db_find_id_hash("organization", "org_id", id)
    
def sdb_user_profile_find_by_user_id(id):
	return db_get_first_dict_column("user_profiles", "user_id", id)

def sdb_user_profile_find_by_prof_id(id):
	return db_get_first_dict_column("user_profiles", "prof_id", id)

def sdb_user_name_update(user_id, first_name, last_name):
	query = "UPDATE user_profiles SET first_name=%s, last_name=%s WHERE user_id=%s" % \
		( db_safestr(first_name), db_safestr(last_name), db_safestr(user_id) )
	db_exec(DB_PROFILES, query)

def sdb_group_profile_valid(id):
	return db_has_record_id("group_profiles", "group_id", id)

def sdb_ldap_group_find(id):
	return db_has_record_id("ldap_groups", "group_id", id)

def sdb_email_part_find(id):
	return db_has_record_id("email_parts", "group_id", id)

def sdb_email_primary_find(user_id):
	return db_get_first_dict(
		"SELECT * FROM emails WHERE user_id=%s AND is_primary = TRUE" % ( db_safestr(user_id) ))

def sdb_email_find(id):
	return db_get_first_dict_column("emails", "user_id", id)

def sdb_user_email_valid(user_id, email):
	query = "SELECT * FROM emails WHERE user_id = %s AND email_address = %s" % ( db_safestr(user_id), db_safestr(email) )
	return db_has_record(query)

def sdb_user_email_find(user_id, email):
	query = "SELECT * FROM emails WHERE user_id = %s AND email_address = %s" % ( db_safestr(user_id), db_safestr(email) )
	return db_get_first_dict(query)

def sdb_user_emails(user_id):
	return db_get_all_dict("SELECT * FROM emails WHERE user_id = %s" % ( user_id ) )

def sdb_user_email_update(user_id, old_email, new_email):
	query = "UPDATE emails SET email_address=%s WHERE user_id=%s AND email_address=%s" % \
		( db_safestr(new_email), db_safestr(user_id), db_safestr(old_email) )
	db_exec(query)

# check org existance
def sdb_org_exists(id):
	query = "select * from organization where org_id=%s" % ( db_safestr(id) )
	return db_has_record(query)
# retro compat
sdb_org_exist = sdb_org_exists

def sdb_org_check(id):
	if sdb_org_exist(id) != True:
		raise KctlException("Organization id %s does not exist" % ( id ))

# check profile existance
def sdb_prof_exist(id):
	query = "select * from profiles where prof_id=%s" % ( db_safestr(id) )
	return db_has_record(query)

def sdb_prof_check(id):
	if sdb_prof_exist(id) != True:
		raise KctlException("Profile id %s does not exist" % ( id ))

# get profile name
def sdb_get_org_kdn(id):
	sdb_org_check(id)
	query = "select name from organization WHERE org_id = %s;" % (db_safestr(id))
	db_debug_query(query)
	return db_get_first_element(query)
# retro compat
sdb_get_org_name = sdb_get_org_kdn
sdb_getorgname = sdb_get_org_kdn

def sdb_org_id_by_kdn(kdn):
	query = "select org_id from organization where name=%s" % ( db_safestr(kdn) )
	db_debug_query(query)
	return db_get_first_element(query)

def sdb_kdn_by_org_id(org_id):
	query = "select name from organization where org_id=%s" % ( db_safestr(org_id) )
	db_debug_query(query)
	return db_get_first_element(query)

def sdb_org_keys(org_id):
	query = "SELECT key_id FROM profiles WHERE org_id=%s" % ( db_safestr(org_id) )
	db_debug_query(query)
	return db_find_list_desc_data(query)

def sdb_get_prof_group_id(prof_id):
	query = "select group_id from profiles where prof_id = %s" % ( db_safestr(prof_id) )
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getprofilegroupid = sdb_get_prof_group_id

def sdb_get_group_prof_id(group_id):
	query = "select prof_id from profiles where group_id = %s" % ( db_safestr(group_id) )
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getgroupprofileid = sdb_get_group_prof_id

def sdb_get_org_profiles(org_id):
	query = "select prof_id from profiles where org_id = %s" % ( db_safestr(org_id) )
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_getorgprofiles = sdb_get_org_profiles

def sdb_get_prof_org_id(prof_id):
	query = "select org_id from profiles where prof_id = %s" % ( db_safestr(prof_id) )
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getprofileorg = sdb_get_prof_org_id

# get profile status
def sdb_get_prof_status(id):
	sdb_prof_check(id)
	query = "select * from get_prof_status(%s);" % (db_safestr(id))
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getprofstatus = sdb_get_prof_status

# get profile name
def sdb_get_prof_name(id):
	sdb_prof_check(id)
	query = "select * from get_profile_name(%s);" % (db_safestr(id))
	db_debug_query(query)
	return db_get_first_element(query)

# Get the primary email address given the profile ID
def sdb_get_prof_pemail(id):
	sdb_prof_check(id)
	query = "select * from get_primary_email_address(%s);" %(db_safestr(id))
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getprimaryemail = sdb_get_prof_pemail

# adds a primary email to a user
def sdb_add_prof_pemail(prof_id, email):
	query = "select add_primary_email(%s, %s);" % (db_safestr(prof_id), db_safestr(email))
	db_debug_query(query)
	db_exec(query)
sdb_addpemail = sdb_add_prof_pemail

# adds an email or email part
def sdb_add_prof_email(prof_id, email):
	query = "select add_email(%s, %s);" % (db_safestr(prof_id), db_safestr(email))
	db_debug_query(query)
	db_exec(query)
sdb_addemail = sdb_add_prof_email

# delete an email or email part
def sdb_rm_email(prof_id, email):
	query = "select del_email(%s, %s);" % (db_safestr(prof_id), db_safestr(email))
	db_debug_query(query)
	db_exec(query)
sdb_rmemail = sdb_rm_email

# List all email address for a profile. 
# FIXME: This is okay to display to the user through KCTL but gives
# horrible results for as an API.  Check db_find_list_desc_data to find out why.
def sdb_ls_prof_emails(prof_id):
	query = "select * from email_ls(%s);" % ( db_safestr(prof_id) )
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lsemail = sdb_ls_prof_emails

def sdb_add_group_prof(org_id, group_name):
	query = "select add_group_profile(%s, %s);" % ( db_safestr(org_id), db_safestr(group_name) )
	db_debug_query(query)
	return db_get_first_element(query)
sdb_addgroup = sdb_add_group_prof

def sdb_set_org_status(org_id, status):
	if status != "":
		query = "select set_org_status(%s, %s);" % (db_safestr(org_id), db_safestr(status))
	else:
		query = "select set_org_status(%s, cast(null as int));" % (db_safestr(org_id))
	db_debug_query(query)
	db_exec(query)

def sdb_add_ldap_group_dn(group_id, group_dn):
	query = "select add_ldap_group(%s, %s);" % ( db_safestr(group_id), db_safestr(group_dn) )
	db_debug_query(query)
	return db_get_first_element(query)
sdb_addldapgroup = sdb_add_ldap_group_dn

def sdb_ls_ldap_groups(group_id):
	query = "select * from ldap_groups where group_id = %s;" % ( db_safestr(group_id) )
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lsldapgroups = sdb_ls_ldap_groups

def sdb_rm_ldap_group(ldap_group_id):
	query = "select del_ldap_group(%s);" % ( db_safestr(ldap_group_id) )
	db_debug_query(query)
	db_exec(query)
sdb_rmldapgroup = sdb_rm_ldap_group

def sdb_get_org_license(kdn):
	query = "select license from organization where name = %s;" % (db_safestr(kdn))
	db_debug_query(query)
	return db_get_first_element(query)

def sdb_set_org_license(kdn, lic):
	query = "select set_org_license(%s, %s);" % ( db_safestr(kdn), db_safestr(lic) )
	db_debug_query(query)
	db_exec(query)

def sdb_add_org(org_name):
	query = "select add_org(%s);" % ( db_safestr(org_name) )
	db_debug_query(query)
	return db_get_first_element(query)
sdb_addorg = sdb_add_org

def sdb_rm_org(org_id):
	query = "select del_org(%s);" % ( db_safestr(org_id) )
	db_debug_query(query)
	db_exec(query)
sdb_rmorg = sdb_rm_org

def sdb_ls_orgs():
	query = "select * from organization_view;"
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lsorg = sdb_ls_orgs

def sdb_get_org_from_KDN(kdn):
	query = "select * from get_org_data_from_kdn(%s)" % (db_safestr(kdn))
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getorgfromkdn = sdb_get_org_from_KDN

def sdb_set_org_forwardto(org_id, forward_to):
	query = "select set_org_forward_to(%s, %s);" % ( db_safestr(org_id), db_safestr(forward_to) )
	db_debug_query(query)
	db_exec(query)
sdb_setorgforwardto = sdb_set_org_forwardto

def sdb_add_user_prof(org_id, first_name, last_name):
	query = "select add_user_profile(%s, %s, %s);" % ( db_safestr(org_id), 
			db_safestr(first_name), db_safestr(last_name) )
	db_debug_query(query)
	return db_get_first_element(query)
sdb_adduser = sdb_add_user_prof

def sdb_rm_prof(prof_id):
	query = "select del_profile(%s);" % ( db_safestr(prof_id) )
	db_debug_query(query)
	db_exec(query)
sdb_rmprofile = sdb_rm_prof

def sdb_ls_profs():
	query = "select * from profiles_view;"
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lsprofiles = sdb_ls_profs

def sdb_set_prof_key(prof_id, key_id):
	query = "select set_key(%s, %s);" % ( db_safestr(prof_id), db_safestr(key_id) )
	db_debug_query(query)
	db_exec(query)
sdb_setkey = sdb_set_prof_key

def sdb_unset_prof_key(prof_id):
	query = "select unset_key(%s);" % ( db_safestr(prof_id) )
	db_debug_query(query)
	db_exec(query)
sdb_disownkey = sdb_unset_prof_key

## KEY MANIPULATION

def sdb_ls_keys():
	query = "select * from pkey_view;"
	db_debug_query(query)
	return db_find_list_desc_data(query)
sdb_lskeys = sdb_ls_keys

def sdb_import_key(key_type, key_id, key_owner, key_data):
	t = (db_safestr(key_type), db_safestr(key_id), db_safestr(key_owner), db_safestr(key_data))
	query = "select import_key(%s, %s, %s, %s);" % t
	db_debug_query(query)
	return db_exec(query) 

def sdb_import_pkey(text, id, owner, data):
	# Backward compatibility.
	if text == "sig": text = "sig_pkey"
	if text == "enc": text = "enc_pkey"

	query = "select import_key(%s, %s, %s, %s);" % ( db_safestr(text), db_safestr(id), db_safestr(owner), db_safestr(data) )
	db_debug_query(query)
	return db_exec(query) 
sdb_importpubkey = sdb_import_pkey

def sdb_import_skey(text, id, owner, data):
	# Backward compability
	if text == "sig": text = "sig_skey"
	if text == "enc": text = "enc_skey"

	query = "select import_key(%s, %s, %s, %s);" % ( db_safestr(text), db_safestr(id), db_safestr(owner), db_safestr(data) )
	db_debug_query(query)
	return db_exec(query) 
sdb_importprivkey = sdb_import_skey

def sdb_get_key(type, id):
	query = "select key_data from keys where key_id=%s and key_type=%s;" % (db_safestr(id), db_safestr(type))
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getkey = sdb_get_key

# return True / False
def sdb_key_valid(key_id):
	query = "select * from pkey_view where key_id = %s;" % ( db_safestr(key_id) )
	db_debug_query(query)
	return db_has_record(query)

def sdb_key_exists(key_type, key_id):
	s = (db_safestr(key_id), db_safestr(key_type))
	query = "select * from keys where key_id = %s and key_type = %s;" % s
	db_debug_query(query)
	return db_has_record(query)
sdb_keyexists = sdb_key_exists

# get key status
def sdb_get_key_status(id):
	query = "select * from get_key_status(%s);" % (db_safestr(id))
	db_debug_query(query)
	return db_get_first_element(query)
sdb_getkeystatus = sdb_get_key_status

# set key status
def sdb_set_key_status(id, status):
	query = "select set_key_status(%s, %s);" % (db_safestr(id), db_safestr(status))
	db_debug_query(query)
	db_exec(query)
sdb_set_key_status = sdb_set_key_status

# check if priv key exists
def sdb_skey_exists(id):
	query = "select key_id from keys where key_id = %s and (key_type = 'enc_skey' or key_type = 'sig_skey');" % ( id )
	db_debug_query(query)
	return db_has_record(query)
sdb_privkeyexists = sdb_skey_exists

# check if pub key exists
def sdb_pkey_exists(id):
	query = "select key_id from keys where key_id = %s and (key_type = 'enc_pkey' or key_type = 'sig_pkey');" % ( id )
	db_debug_query(query)
	return db_has_record(query)
sdb_pubkeyexists = sdb_pkey_exists

# delete public keys
def sdb_rm_keys(id):
	query = "select * from del_key(%s);" % ( db_safestr(id) )
	db_debug_query(query)
	db_exec(query)
sdb_delkeys = sdb_rm_keys

## STATISTICS

def sdb_exportkey(keytype, keyid):
	query = "select * from export_key(%s, %s);" % ( db_safestr(keytype), keyid )
	db_debug_query(query)
	return db_get_all_dict(query)[0]
		
sdb_exportpubkey = sdb_exportkey
sdb_exportprivkey = sdb_exportkey
	
# returns a list: [nb of packagings in the specified (inclusive) interval, total time as h:m:s]
# expects start and stop as UTC seconds from epoch
def sdb_getstatspackagings(start, stop, type=None):
	# timestamps are stored as "Y-m-d h:m:s" (local time)
	start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start))
	stop = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stop))

	query = "select count(*), sum(disconntime - conntime)"
	query = query + " from packagings"
	query = query + " where conntime>='%s' and disconntime<='%s'" % ( start, stop )
	if type != None:
		query = query + " and pkg_type='%d'" % ( type )
	db_debug_query(query)
	return db_get_first_row(query)

# returns a list: [nb of processings in the specified (inclusive) interval, total time as h:m:s]
# expects start and stop as UTC seconds from epoch
def sdb_getstatsprocessings(start, stop, type=None):
	# timestamps are stored as "Y-m-d h:m:s" (local time)
	start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start))
	stop = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stop))

	query = "select count(*), sum(disconntime - conntime)"
	query = query +	" from processings"
	query = query +	" where conntime>='%s' and disconntime<='%s'" % ( start, stop )
	if type != None:
		query = query + " and pkg_type='%d'" % ( type )
	db_debug_query(query)
	return db_get_first_row(query)
