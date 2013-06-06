#!/usr/bin/env python
# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

#####
##### MAIN
#####

from sys import stdout, stderr
import os, sys, string, shutil, ConfigParser, readline, re, time, random, getopt

from kreadline import *

# kctl-lib
from kctllib.kdatabase import *
from kctllib.kparams import *
from kctllib.kexcept import *

import kctlcmd

# kpython
from kout import *

from kreadline import *
	
# This function prints the program usage.
def print_usage(where):
	s = """Usage: kctl                  # interactive mode
       kctl -h               # prints this message
       kctl help [command]   # get help on one or all commands
       kctl [-s] <command> [args] # run command
            '-s' makes kctl put appropriate data in a scriptable format on the first line of output
"""

	if where == 0:
		out_raw(s)
	else:
		err_raw(s)

def main():
	global cmds
	
	kparams_init()

	if kparams_get("debug"):
		do_debug()

	# Parse the options.
	try:
		long_opts = ["db_port=", "debug"]
		(options, cmd_args) = getopt.gnu_getopt(sys.argv[1:], "hsd", long_opts)
		 
	except Exception, e:
		err("Error: '%s'." % str(e))
		print_usage(1)
		sys.exit(1)

	db_port = None

	kparams_set("scriptable", False)
	kparams_set("debug", False)
	
	for opt, val in options:
		if opt == '-h':
			print_usage(0)
			sys.exit(0)
		if opt == '-s':
			kparams_set("scriptable", True)
		if opt == '--db_port':
			db_port = val
		if opt in ("-d", "--debug"):
			kparams_set("debug", True)

	db_init(db_port = db_port)

	intr = CommandInterpreter(kctlcmd.command_classes, "kctl> ", debug_mode = kparams_get("debug"))

	# Run a single command from the command line.
	if len(cmd_args):
		try:
			intr.run_command(cmd_args)
		except Exception, ex:
			if kparams_get("debug"):
				raise
			else:
				sys.stderr.write(str(ex) + "\n")				
		sys.exit(0)

	# if logredirect is active, don't allow interactive mode
	if kparams_get("logredirect"):
		print_usage(0)
		sys.exit(0)
		
	intr.loop()

if __name__ == "__main__":
	main()
