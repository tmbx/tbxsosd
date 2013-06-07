# -*- mode: python; python-indent: 4; tab-width: 4; indent-tabs-mode: t -*-

import tempfile, sys, kbin, shutil
from kexcept import *

# kpython
from kout import *
from kfile import *

def mkdirs(dir):
	if type(dir) != str:
		raise KctlException("bad dir parameter")
	if os.path.isdir(dir):
		pass
	elif os.path.isfile(dir):
		raise KctlException("a file with the same name as the desired dir, '%s', already exists" % (dir) )
	else:
		head, tail = os.path.split(dir)
		if head and not os.path.isdir(head):
	    		mkdirs(head)
		if tail:
			try:
				os.mkdir(dir)
			except:
				raise KctlException("could not create dir '%s'" % (dir))


def kctl_genkeys_cmd_sig(id, file_prefix, owner):
	[skey, pkey] = kctl_gen_sig_key(id, owner)

	sig_skey_path = file_prefix + ".sig.skey"
	kdir = os.path.dirname(sig_skey_path)
	mkdirs(kdir)	
	write_file(sig_skey_path, skey)

	sig_pkey_path = file_prefix + ".sig.pkey"
	kdir = os.path.dirname(sig_pkey_path)
	mkdirs(kdir)
	write_file(sig_pkey_path, pkey)


def kctl_genkeys_cmd_enc(id, file_prefix, owner):
	[skey, pkey] = kctl_gen_sig_key(id, owner)

	enc_skey_path = file_prefix + ".enc.skey"
	kdir = os.path.dirname(enc_skey_path)
	mkdirs(kdir)
	write_file(enc_skey_path, skey)

	enc_pkey_path = file_prefix + ".enc.pkey"
	kdir = os.path.dirname(enc_pkey_path)
	mkdirs(kdir)
	write_file(enc_pkey_path, pkey)


def kctl_keysetid_cmd(id, in_file, out_file):
	key = Key(in_file)
	key.set_id(id)
	key.save(out_file)


def kctl_keysetowner_cmd(owner, in_file, out_file):
	key = Key(in_file)
	key.set_owner(owner)
	key.save(out_file)
	
class Key:
	SIG_PKEY = "sig_pkey"
	SIG_SKEY = "sig_skey"
	ENC_PKEY = "enc_pkey"
	ENC_SKEY = "enc_skey"

	SIG_PAIR = 'sig'
	ENC_PAIR = 'enc'
	
	__key_types_delims = {
		SIG_PKEY : [ "--- START SIGNATURE PUBLIC KEY ---",
					 "--- END SIGNATURE PUBLIC KEY ---" ],
		ENC_PKEY : [ "--- START ENCRYPTION PUBLIC KEY ---",
					 "--- END ENCRYPTION PUBLIC KEY ---" ],
		SIG_SKEY : [ "--- START SIGNATURE PRIVATE KEY ---",
					 "--- END SIGNATURE PRIVATE KEY ---" ],
		ENC_SKEY : [ "--- START ENCRYPTION PRIVATE KEY ---",
					 "--- END ENCRYPTION PRIVATE KEY ---" ]
	}

	__key_types_str = {
		SIG_PKEY : "public signature",
		ENC_PKEY : "public encryption",
		SIG_SKEY : "private signature",
		ENC_SKEY : "private encryption",
	}

	# delete file when deleting object
	is_temp = False

	def fromFile(key_path):
		"""Create a Key instance from a key file."""
		k = Key()
		k.readfile(key_path)
		return k

	def fromBuffer(key_buffer):
		"""Create a Key instance from a buffer."""
		k = Key()
		k.parse(key_buffer)
		k.key_path = tempfile.mktemp()
		k.save()
		k.is_temp = True
		return k

	def fromStrings(key_type, key_id, key_owner, key_data):
		"""Create a Key instance from pre-parsed data."""
		k = Key()
		k.id = str(key_id)
		k.owner = key_owner
		k.key = key_data.replace("\n", "")
		k.type = key_type
		k.key_path = tempfile.mktemp()
		k.save()
		k.is_temp = True
		return k

	def newPair(key_type, key_id, key_owner):
		"""Create a new pair of keys.  The keys are backed by files
		created in a temporary directory.  Use the save method if you
		want to copy them somewhere else."""
		key_dir = tempfile.mkdtemp()
		kbin.genkeys(key_type = key_type,
					 key_id = key_id,
					 key_owner = key_owner,
					 key_filename = os.path.join(key_dir, "key"))
		pkey = Key.fromBuffer(read_file(os.path.join(key_dir, "key.%s.pkey" % key_type)))
		skey = Key.fromBuffer(read_file(os.path.join(key_dir, "key.%s.skey" % key_type)))
		shutil.rmtree(key_dir)
		return (pkey, skey)
		
	fromFile = staticmethod(fromFile)
	fromBuffer = staticmethod(fromBuffer)
	fromStrings = staticmethod(fromStrings)
	newPair = staticmethod(newPair)

	def readfile(self, key_path):
		self.key_path = key_path
		content = read_file(key_path)
		self.parse(content)
	
	def parse(self, content):
		lines = content.strip("\n").split("\n");
		if len(lines) < 5:
			raise KctlException("key file invalid")
		for type in self.__key_types_delims:
			if lines[0] == self.__key_types_delims[type][0] and lines[len(lines)-1] == self.__key_types_delims[type][1]:
				self.type = type

		if type != None:
			self.type_str = self.__key_types_str[self.type]

		self.id = lines[1]
		self.owner = lines[2]
		self.key = "".join(lines[3:-1])

	def save(self, key_path = None):
		"""Save the key into its file or another file and reload the
		key from the file, using the new file as the default file if
		provided."""
		data  = ""
		data = data + self.__key_types_delims[self.type][0] + "\n"
		data = data + self.id + "\n" # id is a string because
		data = data + self.owner + "\n"
		data = data + self.key + "\n"
		data = data + self.__key_types_delims[self.type][1] + "\n"
		if key_path:
			write_file(key_path, data);
		else:
			write_file(self.key_path, data)

	def setkeyid(self, newid):
		"""Change the key ID."""
		self.save()
		newfile = self.key_path + "-NEW"
		kbin.setkeyid(newid, self.key_path, newfile)
		try:
			shutil.move(newfile, self.key_path)
		except:
			os.unlink(newfile)
			raise
		self.readfile(self.key_path)

	def setkeyname(self, newowner):
		"""Change the key owner name."""
		self.owner = newowner
		self.save()

	def delete(self):
		if os.path.exists(self.key_path):
			if os.path.isfile(self.key_path) and not os.path.islink(self.key_path):
				os.unlink(self.key_path)
			else:
				raise KctlException("Key file %s is not a regular file: not deleting.")
		self.owner = None
		self.id = None
		self.key = None
	
	def __str__(self):
		return "[key: id=%s, owner=%s, type=%s]" % (self.id, self.owner[0:99], self.type_str)

	def __eq__(self, other_key):
		if not other_key.__class__ is Key:
			return False
		return (other_key.id == self.id and \
				other_key.owner == self.owner and \
				other_key.key == self.key)

	def __del__(self):
		if self.is_temp:
			if os.path.exists(self.key_path):
				os.unlink(self.key_path)
