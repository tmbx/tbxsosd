# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

#####
##### GET CONFIGS FROM TBXSOSD
#####

# using regexps - could be improved...

import re, os, os.path

# kpython
from kfile import *
from krun import *
from kodict import odict
from kexcept import *

# port from ruby
class KTbxsosdConfig:
	class Value:
		def __init__(self, key, value = None, hasChanged = False):
			self.value = value
			self.key = key
			self.hasChanged = hasChanged

		def __str__(self):
			return "%s = \"%s\";" % (self.key, self.value)

	def __init__(self, source_file, user_file = None):
		self.options = odict()

		self.allowChanges = True
		if not user_file:
			self.allowChanges = False
		
		# read main file, which contains include commands
		main_conf = read_file(source_file)

		# m4 parses the include commands and read files
		conf_dir = os.path.dirname(source_file)
		proc = KPopen(main_conf, "/usr/bin/m4", "-I", conf_dir)

		out = proc.stdout
		err = proc.stderr
		status = proc.return_code

		if status != 0:
			raise Exception("Could not read config")

		# out is a string containing all included files in tbxsosd.conf
		self.load_string(out)

		# Open the local configuration file if it exists.
		if user_file:
			local_conf = read_file(user_file)
			self.load_string(local_conf, setChanged = True)

	# load configs from string
	def load_string(self, data, setChanged = False):
		for line in data.split("\n"):
			p = re.compile(r'^([^#\s]+)\s*=\s*"(.*)";')
			m = p.match(line)
			if m != None:
				key = m.group(1).strip()
				val = m.group(2).strip()
				v = self.Value(key, val, hasChanged = setChanged)
				self.options[key] = v

	# Get all the options
	def all(self): return self.options.keys()

	# Get an option string.
	def get(self, key):
		if key in self.options.keys():
			return self.options[key].value
		return ""

	# Set an option string.
	def set(self, key, value):
		if self.allowChanges:
			self.options[key] = self.Value(key, value, hasChanged = True)
		else:
			raise KctlException("Cannot change configuration without an user-modifiable configuration file.")

	def save(self, target_file):
		conf_file = file(target_file, "w")
		for item in self.options.items():
			(key, value) = item
			if value.hasChanged:
				conf_file.write(str(value) + "\n")
