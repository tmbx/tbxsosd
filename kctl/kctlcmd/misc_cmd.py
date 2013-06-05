# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

from kctllib.kdatabase import *
from kctllib.kparams import *

# kpython
from kreadline import Command

from misc import *				

class SignLicenseCommand(Command):
	Name = "signlicense"
	Syntax = "<KDN> [<parent KDN>|""] <seat limit> <seat maximum> [is reseller?] <capabilities integer>"
	Help = "Sign a license file."
	MaxParams = 0
	MinParams = 0

	def run(self, interpreter, kdn, parent_kdn = None):
		return run_external_kctlbin(["signlicense",
									 kdn, parent_kdn,
									 lim_seats, max_seats, is_reseller, caps])

class SelfTestCommand(Command):
	Name = "selftest"
	Syntax = ""
	Help = "Test connection to the database(s)."
	MaxParams = 0
	MinParams = 0

	def run(self, interpreter, args = None):
		db_conn_all()
		out("Could connect to all databases.")

class PurgeKOSKDN(Command):
	Name = "purgekoskdn"
	Syntax = "<KDN>"
	Help = "Purge KDN from KOS. DANGEROUS COMMAND."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, kdn):	
		# check if kdn is found
		# on kos, org name is kdn
		try:
			org_id = sdb_org_id_by_kdn(kdn)
		except:
			raise KctlCommandError("KDN not found.")
		# get keys associated to this org
		field_descs, res = sdb_org_keys(org_id)
		keys = []
		if field_descs != None and res != None:
			for row in res:
				if row[0] != None:
					keys.append(row[0])
		# remove duplicates
		keyids = list(set(keys))
		# delete keys
		for key_id in keys:
			if sdb_pubkeyexists(key_id):
				sdb_rm_keys(key_id)
			if sdb_privkeyexists(key_id):
				sdb_rm_keys(key_id)
		# delete all profiles associated to that kdn (org)
		field_descs, res = sdb_getorgprofiles(org_id)
		if field_descs != None and res != None:
			for row in res:
				sdb_rmprofile(row[0]) # row[0] => prof_id
		# delete org
		sdb_rmorg(org_id)
		db_commit()
		out("Purged KOS kdn '%s'" % ( aaa(kdn) ))

class CleanDBCommand(Command):
	Name = "cleandb"
	Syntax = "cleandb [check|clean]"
	Help = "Try to clean invalid data in the database."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, mode):
		if not (mode == "check" or mode == "clean"):
			raise KctlCommandError("bad parameter")

		# PROFILES CHECKING / CLEANING
		for profile in sdb_profiles_find():
			prof_id = profile["prof_id"]
			user_id = profile["user_id"]
			group_id = profile["group_id"]
			prof_type = profile["prof_type"]
			key_id = profile["key_id"]

			errors = []

			# no key associated
			if not key_id:
				errors.append("profile %s has no key set" % ( str(prof_id) ))
			# invalid key
			elif not sdb_key_valid(key_id):
				errors.append("profile %s has an invalid key (%s)" % ( str(prof_id), str(key_id) ))

			# invalid type of profile
			if prof_type != "U" and prof_type != "G":
				errors.append("profile %s has an invalid type '%s'" % ( str(prof_id), str(prof_type) ))

			# profile is a local user
			elif prof_type == "U":
				# check if login found
				if not sdb_login_find(prof_id):
					errors.append("profile %s has no login associated" % ( str(prof_id) ))

				if not user_id:
					errors.append("profile %s has no user profile id set" % ( str(prof_id) ))
				elif not sdb_user_profile_valid(user_id):
					errors.append("profile %s has an invalid user profile associated" % ( str(prof_id) ))
				elif not sdb_email_primary_find(user_id):
					errors.append("profile %s has no primary email associated" % ( str(prof_id) ))
					
			# profile is a group
			elif prof_type == 'G':
				# check if group specified and valid
				if not group_id:
					errors.append("profile %s has no group profile id set" % ( str(prof_id) ))
				elif not sdb_group_profile_valid(group_id):
					errors.append("profile %s has an invalid group profile associated" % ( str(prof_id) ))
				else:
					# got a valid group - check ldap_group and email_parts
					# disabled - scrary
					pass
					if not sdb_ldap_group_find(group_id):
						errors.append("profile %s has no ldap group associated" % ( str(prof_id) ))
					if not sdb_email_part_find(group_id):
						errors.append("profile %s has no email part associated" % ( str(prof_id) ))

			if len(errors):
				out("\n".join(errors))
				if mode == "check":
					out("WARNING: WOULD PURGE PROFILE %s" % ( prof_id ))
				if mode == "clean":
					out("WARNING: PURGING PROFILE %s" % ( prof_id ))
					sdb_rmprofile(prof_id)

		# LOGINS CHECKING / CLEANING
		for login in sdb_logins_find():
			errors = []
			user_name = login["user_name"]
			prof_id = login["prof_id"]

			errors = []

			if not prof_id:
				errors.append("login %s has no profile associated" % ( str(user_name) ))
			elif not sdb_profile_find(prof_id):
				errors.append("login %s has an invalid profile id associated" % ( str(user_name) ))

			if len(errors) > 0:
				out("\n".join(errors))
				if mode == "check":
					out("WARNING: WOULD PURGE LOGIN %s" % ( user_name ))
				if mode == "clean":
					out("WARNING: PURGING LOGIN %s" % ( user_name ))
					sdb_rmlogin(user_name)

		if mode == "clean":
			db_commit()
			out("tbxsosd database clean.")

		
