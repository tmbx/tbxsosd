# -*- mode: python; python-indent: 4; tab-width: 4 -*-

import os

from kctllib.kiniconfig import *

# kpython
from kout import *

kparams = {}

def kparams_init():
	global kparams
	kparams["logredirect"] = False
	kparams["debug"] = False
	kparams["commit"] = True
	kparams["db_debug_query"] = False
	kparams["kctl"] = "/usr/bin/kctl"
	kparams["kctlbin"] = "/usr/bin/kctlbin"

	# try to load params from ini config
	try:
		config = KIniConfig()
		for key in ["logredirect", "debug", "commit", "db_debug_query", "kctl", "kctlbin"]:
			tmpvalue = config.get("main", key)
			if tmpvalue != None:
				kparams[key] = tmpvalue

	except:
		pass


	# can override some params with an env var
	if os.environ.get("LOGREDIRECT") != None:
		kparams["logredirect"] = True
	if os.environ.get("DEBUG") != None:
		kparams["debug"] = True
	if os.environ.get("NO_COMMIT") != None:
		kparams["commit"] = False
	if os.environ.get("DB_DEBUG_QUERY") != None:
		kparams["db_debug_query"] = True
	if os.environ.get("KCTL") != None:
		kparams["kctl"] = os.environ.get("KCTL")
	if os.environ.get("KCTLBIN") != None:
		kparams["kctlbin"] = os.environ.get("KCTLBIN")

	# log redirect
	if kparams["logredirect"]:
		do_logredirect()

	# print some params if...
	if kparams["debug"]:
		out("DEBUG is active.")
	if not kparams["commit"]:
		out("NO_COMMIT is active: no activity will be commited.")
	if kparams["db_debug_query"]:
		out("DB_DEBUG_QUERY is active.")

	# debug
	if kparams["debug"]:
		do_debug()
		debug(str(kparams))


def kparams_get(key):
	global kparams
	try:
		return kparams[key]
	except:
		return None

def kparams_set(key, value):
	global kparams
	kparams[key] = value

kparams_init()
