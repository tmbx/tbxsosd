# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

from kctllib.kdatabase import *
from kctllib.kparams import *
from kctllib.kexcept import *

# kpython
from kreadline import Command

from misc import *

# Functions tested automatically in kctl_test.

class LsOrgCommand(Command):
    Name = "lsorg"
    Syntax = ""
    Help = "List all organizations currently in the database."
    MaxParams = 0
    MinParams = 0

    def run(self, interpreter, args = None):
        field_descs, res = sdb_lsorg()
        if res:
            print_tabbed_results(field_descs, res)

class AddOrgCommand(Command):
	Name = "addorg"
	Syntax = "<organization name>"
	Help = "Add a new organization."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, org_name):	
		org_id = sdb_addorg(org_name)
		db_commit()
		scriptable_out("%s" % ( bbb(org_id) ))
		out("Added organization no: %s." % ( aaa(org_id) ))

class PurgeOrgCommand(Command):
	Name = "purgeorg"
	Syntax = "<organization ID>"
	Help = "Remove an organization from the DB, with all its dependencies."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, org_id):
		org_id = int(org_id)
		try:
			org_name = sdb_getorgname(org_id)
		except NoRow:
			raise KctlCommandError("organization not found.")
		field_descs, res = sdb_getorgprofiles(org_id)
		if field_descs != None and res != None:
			for row in res:
				sdb_rmprofile(row[0]) # row[0] => prof_id
		sdb_rmorg(org_id)
		db_commit()
		out("Purged organization no: %s (%s)" % (aaa(org_id), aaa(org_name)))

class RmOrgCommand(Command):
	Name = "rmorg"
	Syntax = "<organization ID>"
	Help = "Remove an organization from the DB, not touching its dependencies."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, org_id):
		org_id = int(org_id)
		sdb_rmorg(org_id)
		db_commit()
		out("Deleted organization no: %s" % (aaa(org_id)))

class SetOrgForwardToCommand(Command):
	Name = "setorgforwardto"
	Syntax = "<organization ID> [<forward email address>]"
	Help = "Set the forwarding address.  Empty to disable."
	MaxParams = 2
	MinParams = 1

	def run(self, interpreter, org_id, forward_to = ""):
		sdb_setorgforwardto(int(org_id), forward_to)
		db_commit()
		out("Set forward_to for org_id '%s' to '%s'" % (aaa(int(org_id)), aaa(forward_to) ))

class SetOrgStatusCommand(Command):
	Name = "setorgstatus"
	Syntax = "<organization ID> [<status>]"
	Help = "Set the organization activation status."
	MaxParams = 2
	MinParams = 1

	def run(self, interpreter, org_id, status = ""):
		sdb_set_org_status(int(org_id), status)
		db_commit()
		out("Set status for org_id '%s' to '%s'" % (aaa(int(org_id)), aaa(status)))

# Functions not tested automatically.

class ShowLicenseCommand(Command):
	Name = "showlicense"
	Syntax = "<KDN>"
	Help = "Dump the license data for an organization."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, kdn):
		# Import license from DB to temporary file.
		lic = sdb_get_org_license(kdn)
		if lic and lic != "":
			(tf, tf_name) = mkstemp()
			os.write(tf, lic)
			# Call kctlbin showlicense on temporary file.
			run_external_kctlbin(["showlicensefile", tf_name])
			os.close(tf)
		else:
			out("No license for KDN %s" % kdn)

class ImportLicenseCommand(Command):
	Name = "importlicense"
	Syntax = "<license file>"
	Help = "Set the license for an organization."
	MaxParams = 1
	MinParams = 1
	
	def run(self, interpreter, license_file):
		f = open(license_file, "r")
		lic = f.read()
		f.close()

		# Extract the KDN from the license file.
		kctlbin = kparams_get("kctlbin")
		cmd = [kctlbin, "showlicensefile", license_file]
		proc = KPopen("", cmd)
		lines = re.split("\n", proc.stdout)
		# Get the first line.
		(v, kdn) = re.split(": ", lines[0])
		if v != "kdn":
			out("Unable to guess which KDN to use to import the license")
		else:
			sdb_set_org_license(kdn, lic)
			out("Set license file %s to KDN %s" % ( license_file, aaa(kdn) ))
			db_commit()  
