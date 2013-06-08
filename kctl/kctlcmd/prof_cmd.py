# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

from kctllib.kdatabase import *
from kctllib.kparams import *

# kpython
from kreadline import Command

from misc import *

# Functions tested automatically in kctl_test.

class AddUserCommand(Command):
    Name = "adduser"
    Syntax = "<organization ID> <first name or name> [<last name>]"
    Help = "Add a new user profile in the database."
    MaxParams = 3
    MinParams = 2

    def run(self, interpreter, org_id, first_name, last_name = None):
        if not last_name:
            if first_name.find(" "):
                first_name, last_name = first_name.split(" ", 1)
            else:
                first_name = ""
                last_name = ""

        prof_id = sdb_adduser(org_id, first_name, last_name)
        db_commit()
        scriptable_out("%s" % (bbb(prof_id)))
        out("Added user %s with profile ID %s" % (aaa(first_name + " " + last_name), aaa(prof_id)))

class RmProfileCommand(Command):
    Name = "rmprofile"
    Syntax = "<profile ID>"
    Help = "Remove a group profile."
    MaxParams = 1
    MinParams = 1

    def run(self, interpreter, prof_id):
        prof_id = int(prof_id)
        sdb_rmprofile(prof_id)
        db_commit()
        out("Deleted profile no: %s" % ( aaa(prof_id) ))

class AddPrimaryEmailCommand(Command):
    Name = "addpemail"
    Syntax = "<profile ID> <email address>"
    Help = "Set the user primary email address."
    MaxParams = 2
    MinParams = 2

    def run(self, interpreter, prof_id, email):
        prof_id = int(prof_id)
        prof_name = sdb_get_prof_name(prof_id)
        sdb_addpemail(prof_id, email)
        db_commit()
        out("Added primary email address %s to %s" % ( aaa(email), aaa(prof_name) ))

class AddEmailCommand(Command):
    Name = "addemail"
    Syntax = "<profile ID> <email address>"
    Help = "Add a secondary email address to a profile."
    MaxParams = 2
    MinParams = 2

    def run(self, interpreter, prof_id, email):
        prof_id = int(prof_id)
        prof_name = sdb_get_prof_name(prof_id)
        sdb_addemail(prof_id, email)
        db_commit()
        out("Added secondary email address %s to %s" % ( aaa(email), aaa(prof_name) ))

class RmEmailCommand(Command):
    Name = "rmemail"
    Syntax = "<profile ID> <email address>"
    Help = "Remove an email or an email part from a profile."
    MaxParams = 2
    MinParams = 2

    def run(self, interpreter, prof_id, email):
        prof_id = int(prof_id)
        sdb_rmemail(prof_id, email)
        db_commit()
        out("Removed email address %s from %s" % ( aaa(email), aaa(prof_name) ))

class LsEmailCommand(Command):
    Name = "lsemail"
    Syntax = "<profile ID>"
    Help = "List emails or emails parts for a group."
    MaxParams = 1
    MinParams = 1

    def run(self, interpreter, prof_id):
        prof_id = int(prof_id)
        field_descs, res = sdb_lsemail(prof_id)
        if res:
            print_tabbed_results(field_descs, res)

class LsProfilesCommand(Command):
    Name = "lsprofiles"
    Syntax = "[full]"
    Help = "List all the profiles, print associated emails if 'full' is mentioned"
    MaxParams = 1
    MinParams = 0

    def run(self, interpreter, full = None):
        field_descs, res = sdb_lsprofiles()
		if res:
			if not full or full != "full":
				# Default behavior.
				print_tabbed_results(field_descs, res)
			else:
				# Full profile data.  Be prepared! This is extremely
				# ugly.
 				logins_data = sdb_lslogin()[1]
 				logins = {}
 				for l in logins_data:
 					prof_id = l[1]
 					logins[prof_id] = [l[2], l[3]]
					
				new_res = []
				for prof in res:
					if prof[1] in logins:
						prof += logins[prof[1]]
					else:
						prof += ["None", "None"]
					sys.stdout.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t" % tuple(prof))
					emails = sdb_lsemail(int(prof[1]))[1]
					emails_ls = []
					if emails:
						for e in emails:
							if e[0].endswith(" *"):
								emails_ls.append(e[0].replace(" *", ""))
							else:
								emails_ls.append(e[0])
					sys.stdout.write(" ".join(emails_ls) + "\n")
			
class SetKeyCommand(Command):
	Name = "setkey"
	Syntax = "<profile ID> <key>"
	Help = "Set a key ID to a profile."
	MaxParams = 2
	MinParams = 2
	
	def run(self, interpreter, prof_id, key_id):
		prof_id = int(prof_id)
		key_id = int(key_id)

		sdb_setkey(prof_id, key_id)
		db_commit()
		out("Set key no %s to profile %s" % (aaa(key_id), aaa(prof_id) ))

class DisownKeyCommand(Command):
	Name = "disownkey"
	Syntax = "<profile ID>"
	Help = "Disown a key from a profile."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, prof_id):
		prof_id = int(prof_id)

		sdb_disownkey(prof_id)
		db_commit()
		out("Unset key of profile %s" % ( aaa(prof_id) ))

# Functions not tested automatically.

class SetProfStatusCommand(Command):
	Name = "getprofstatus"
	Syntax = "<profile ID>"
	Help = "Get the status integer of a profile ID."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, prof_id):
		prof_id = int(prof_id)

		val = sdb_getprofstatus(id)
		 # prints profile status on first line if scriptable option is enabled
		scriptable_out("%s" % ( bbb(val) ))
		out("Profile ID %s status is %s" % (aaa(id), aaa(val)))

class AddGroupCommand(Command):
    Name = "addgroup"
    Syntax = "<organization ID> <group name>"
    Help = "Add a new group profile in the database."
    MaxParams = 2
    MinParams = 2

    def run(self, interpreter, org_id, group_name):
        org_id = int(org_id)
        
        org_name = sdb_get_org_name(org_id)
        group_id = sdb_addgroup(org_id, group_name)
        db_commit()
        scriptable_out("%s" % (bbb(group_id)))
        out("Added group %s to organization %s." % ( aaa(group_id), aaa(org_id) ))
