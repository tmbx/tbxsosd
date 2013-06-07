# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

from kctllib.kdatabase import *
from kctllib.kparams import *

# kpython
from kreadline import Command

from misc import *

# Functions tested automatically in kctl_test.

class AddLoginCommand(Command):
	Name = "addlogin"
	Syntax = "<profile_id> <org_id> <login> [<password>]"
	Help = "Add an user login in the database."
	MaxParams = 4
	MinParams = 3

	def run(self, interpreter, prof_id, org_id, username, password = None):
		prof_id = int(prof_id)
		org_id = int(org_id)

		if not password:
			password = askpassword()

		org_id = sdb_getprofileorg(prof_id)
		sdb_addlogin(org_id, prof_id, username, password)
		db_commit()
		out("Login %s added to profile %s (organization %s)" % (aaa(username), aaa(prof_id), aaa(org_id)))

class RmLoginCommand(Command):
	Name = "rmlogin"
	Syntax = "<login>"
	Help = "Remove an user login from the database."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, login):
		login = login
		sdb_rmlogin(login)
		db_commit()
		out("Login %s removed" % ( aaa(login) ))

class LsLoginCommand(Command):
	Name = "lslogin"
	Syntax = ""
	Help = "List all login currently in the database."
	MaxParams = 0
	MinParams = 0

	def run(self, interpreter, args = None):
		field_descs, res = sdb_lslogin()
		if res:
			print_tabbed_results(field_descs, res)

# Functions not tested automatically.

class FreeLoginSeatCommand(Command):
	Name = "freeloginseat"
	Syntax = ""
	Help = "Free login seat."
	MaxParams = 2
	MinParams = 2

	def run(self, interpreter, org_id, username):
		org_id = int(org_id)

		sdb_freeloginseat(org_id, username)
		db_commit()
		out("Freed seat used by username %s, org %s" % (aaa(username), aaa(org_id)))

class LsSeatAllocation(Command):
	Name = "lsseatallocation"
	Syntax = ""
	Help = "List seats allocation."
	MaxParams = 0
	MinParams = 0

	def run(self, interpreter, args = None):
		field_descs, res = sdb_lsseatsallocation()
		if res:
			print_tabbed_results(field_descs, res)

class LsSeatOrg(Command):
	Name = "lsseatorg"
	Syntax = "<org_id>"
	Help = "List seats for org_id."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, org_id):
		org_id = int(org_id)

		field_descs, res = sdb_lsseatsorg(org_id)
		if res:
			print_tabbed_results(field_descs, res)

class SetSeatAllocation(Command):
	Name = "setseatallocation"
	Syntax = "<parent org ID> <org ID> <number>"
	Help = "Set seats available for org_id."
	MaxParams = 3
	MinParams = 3

	def run(self, interpreter, parent_org_id, org_id, number):
		if p_org_id == "":
			p_org_id = None
		if int(number) < 0:
			err("Invalid parameter. Number should be > 0.")
			return 1
		available = get_seats_available_to_allocate(p_org_id, org_id)
		if int(number) > available:
			err("Not enough seats available for allocation: org %s has only %s seats available for allocation." % ( aaa(p_org_id), str(available) ) )
			return 1
		sdb_setseatsallocation(p_org_id, org_id, number)
		db_commit()
		out("Set usable seats count to %s for organization %s" % ( aaa(number), aaa(org_id) ))

