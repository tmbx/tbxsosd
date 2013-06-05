# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

#####
##### GET CONFIGS FROM INI FILE
#####

import os
import ConfigParser

from kctllib.kexcept import *

# kpython
from kout import *
from kfile import *

# loads config from an ini file
# if override_conf is present, try only from this file
# otherwise, try ~/.kctl.ini first, and then try /etc/teambox/kctl.ini
# NOTE: override_conf is not implemented in the application yet !!!
class KIniConfig:
	def __init__(self, override_conf=None):
		file = self.search_ini(override_conf)
		if file == None:
			raise KctlException("could not find any ini file")
		self.parser = ConfigParser.ConfigParser()
		try:
			self.parser.readfp(open(file))
		except Exception, e:
			raise KctlException("could not read config file %s: %s" % ( file, str(e) ) )

	def search_ini(self, override_conf):
		config_files = []

		if override_conf != None:
			# specified a config file - try this file ONLY
			config_files.append(override_conf)
		else:
			# ~/.kctl.ini
			dir = os.environ.get("HOME")
			if dir != None:
				config_files.append(os.path.join(dir, ".kctl.ini"))

			# /etc/teambox/kctl.ini
			config_files.append("/etc/teambox/kctl.ini")

		for file in config_files:
			try:
				# try to read the file.. if readable, return this file
				check_file_readable(file, raise_on_error = True)
				return file
			except Exception, ex:
				debug("file %s does not exist or is not readable" % ( file ) )

		return None

	def get(self, section, key):
		try:
			debug("kiniconfig.get(%s,%s)" % ( section, key ) )
			return self.parser.get(section, key)
		except:
			return None




### BEGIN_TESTS ###

def parser_tests_run():
	print "BEGIN"
	#do_debug()
	config = KIniConfig()
	print config.get("databases", "db_login.name")
	print "END"


if __name__ == "__main__":
	parser_tests_run()

### END_TESTS ###

