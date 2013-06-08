# -*- mode: python; tab-width: 4; indent-tabs-mode: t; python-indent: 4 -*-

from kctllib.kdatabase import *
from kctllib.kparams import *
from kctllib.kkeys import *

# kpython
from kreadline import Command

from misc import *

class LsKeysCommand(Command):
	Name = "lskeys"
	Syntax = ""
	Help = "List all keys in database + profile they are associated with."
	MaxParams = 0
	MinParams = 0

	def run(self, interpreter, args = None):
		field_descs, res = sdb_lskeys()
		if res:
			print_tabbed_results(field_descs, res)

class RmKeysCommand(Command):
	Name = "rmkeys"
	Syntax = "<key ID>"
	Help = "Remove public and private keys with id <key_id>."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, key_id):
		key_id = int(key_id)
	
		# should check if key is bound to a users or groups
		sdb_delkeys(key_id)
		db_commit()
		out("Delete public and private keys %s" % (aaa(key_id)))

class KeySetIDCommand(Command):
	Name = "keysetid"
	Syntax = "<input file> <new id> <output file>"
	Help = "Change the internal key ID of a key."
	MaxParams = 3
	MinParams = 3

	def run(self, interpreter, in_file, key_id, out_file):
		key_id = int(key_id)
		return run_external_kctlbin(["keysetid", str(in_file), str(key_id), str(out_file)])		

class KeySetNameCommand(Command):
	Name = "keysetname"
	Syntax = "<input file> <new name> <output file>"
	Help = "Change the internal key name of a key."
	MaxParams = 3
	MinParams = 3

	def run(self, interpreter, in_file, key_name, out_file):
		return run_external_kctlbin(["keysetname", in_file, key_name, out_file])

class PrintKeyCommand(Command):
	Name = "printkey"
	Syntax = ""
	Help = "Print the information contained in a key."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, key_file):
		run_external_kctlbin(["printkey", key_file])

class ImportKeyCommand(Command):
	Name = "importkey"
	Syntax = "<input file>"
	Help = "Import a key file."
	MaxParams = 1
	MinParams = 1

	def run(self, interpreter, in_file):
		key = Key.fromFile(in_file)
		if key.type == Key.SIG_PKEY:
			sdb_importpubkey("sig", key.id, key.owner, key.key)
		elif key.type == Key.SIG_SKEY:
			sdb_importprivkey("sig", key.id, key.owner, key.key)
		elif key.type == Key.ENC_PKEY:
			sdb_importpubkey("enc", key.id, key.owner, key.key)
		elif key.type == Key.ENC_SKEY:
			sdb_importprivkey("enc", key.id, key.owner, key.key)
		db_commit()
		out("Imported or updated key %s" % (aaa(str(key))))

# Export keys to a files beginning with prefix.
class ExportKeysCommand(Command):
	Name = "exportkeys"
	Syntax = "<key ID> <file prefix>"
	Help = "Export a set of key from the database."
	MaxParams = 2
	MinParams = 2

	def run(self, interpreter, key_id, file_prefix):
		try:
			k = sdb_getkey("sig_pkey", key_id)
			key = Key.fromStrings(key_type = Key.SIG_PKEY,
								  key_id = key_id,
								  key_owner = "unknown",
								  key_data = k)
			key.save(file_prefix + ".sig.pkey")
		except:
			out("no sig pkey")

		try:
			k = sdb_getkey("sig_skey", key_id)
			key = Key.fromStrings(key_type = Key.SIG_SKEY,
								  key_id = key_id,
								  key_owner = "unknown",
								  key_data = k)
			key.save(file_prefix + ".sig.skey")
		except:
			out("no sig skey")

		try:
			k = sdb_getkey("enc_pkey", key_id)
			key = Key.fromStrings(key_type = Key.ENC_PKEY,
								  key_id = key_id,
								  key_owner = "unknown",
								  key_data = k)
			key.save(file_prefix + ".enc.pkey")
		except:
			out("no enc pkey")

		try:
			k = sdb_getkey("enc_skey", key_id)
			key = Key.fromStrings(key_type = Key.ENC_SKEY,
								  key_id = key_id,
								  key_owner = "unknown",
								  key_data = k)
			key.save(file_prefix + ".enc.skey")
		except:
			out("no enc skey")

		db_commit()
		out("Exported key to %s...." % ( file_prefix ))

class ExportKeyCommand(Command):
	Name = "exportkey"
	Syntax = "<key id> [sig_skey|sig_pkey|enc_skey|enc_pkey] <output file>"
	Help = "Export a key file"
	MaxParams = 3
	MinParams = 3

	def run(self, interpreter, key_id, key_type, out_file):
		key_id = int(key_id)
		
		s = sdb_exportkey(key_type, key_id)
		if not s:
			out("Key ID %d not found." % key_id)
		else:
			key = Key.fromStrings(key_owner = s["owner_name"], 
								  key_data = s["key_data"],
								  key_type = key_type,
								  key_id = s["key_id"])
			key.save(out_file);
		
class GenKeysCommand(Command):
	Name = "genkeys"
	Syntax = "[enc|sig|both] <key id> <keyfile name> <owner>"
	Help = "Generate a group of key of ID 'keyid' owned by 'owner'"
	MaxParams = 4
	MinParams = 4

	def run(self, interpreter, key_type, key_id, key_filename, key_owner):
		run_external_kctlbin(["genkeys", str(key_type), str(key_id), str(key_filename), str(key_owner)])

class GetKeyStatusCommand(Command):
	Name = "getkeystatus"
	Syntax = "<key ID>"
	Help = "Get the status integer of a key ID owner."
	MaxParams = 1
	MinParams = 1
	
	def run(self, interpreter, key_id):
		key_id = int(key_id)
		
		status_value = sdb_getkeystatus(key_id)
		
		 # prints key status on first line if scriptable option is enabled
		scriptable_out("%s" % (bbb(status_value)))
		out("Key ID %s owner status is %s" % (aaa(key_id), aaa(status_value)))

class SetKeyStatusCommand(Command):
	Name = "setkeystatus"
	Syntax = "<key ID> <status>"
	Help = "Set the key status integer of a key."
	MaxParams = 2
	MinParams = 2

	def run(self, interpreter, key_id, status_value):
		sdb_setkeystatus(key_id, status_value)
		db_commit()
		out("Status of the owner of key %s set to %s" % (aaa(key_id), aaa(status_value)))



