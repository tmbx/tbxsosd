# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

from kctllib.kdatabase import *
from kctllib.kparams import *

# kpython
from kreadline import Command
from krun import *

def run_external_kctlbin(params):
    kctlbin = kparams_get("kctlbin")
    if kparams_get("commit") == False:
        err("error: tried to call an external program in no_commit mode.")
        return 1
    cmd = [kctlbin] + params
    proc = KPopen("", cmd) # "" is data sent to stdin
    out_raw(proc.stdout)
    err_raw(proc.stderr)
    return proc.return_code

def genkeys(key_type = "both",
			key_id = None,
			key_filename = None,
			key_owner = None):
    if key_id is None:
        raise KctlException("key_id needs to be defined")
    if key_filename is None:
        raise KctlException("key_filename needs to be defined")
    if key_owner is None:
        raise KctlException("key_owner needs to be defined")
    
    run_external_kctlbin(["genkeys", key_type, str(key_id), key_filename, key_owner])

def setkeyid(key_id, input_key_file, output_key_file):
	run_external_kctlbin(["keysetid", input_key_file, str(key_id), output_key_file])

class License:
	def __init__(self):
		self.kdn = None
		self.parent_kdn = None
		self.best_after = None
		self.best_before = None
		#self.capacities = None
		self.lim_seat = None
		self.max_seat = None
		self.reseller = None

def showlicense(kdn = None, org_id = None):
	def _nullproof(val):
		if val == "(null)":
			return None
		else:
			return val

	lic_b64 = sdb_get_org_license(kdn)
	lic_obj = None
	if lic_b64 and lic_b64 != "":
		(tf, tf_name) = mkstemp()
		try:
			os.write(tf, lic_b64)
			lic_obj = License()
			lic_data = get_cmd_output(["kctlbin", "showlicensefile", tf_name])
			for lic_line in lic_data.strip().split("\n"):
 				(key, val) = lic_line.split(":", 2)
				if key.strip() == "kdn":
					lic_obj.kdn = _nullproof(_nullproof(val.strip()))
				elif key.strip() == "parent kdn":
					lic_obj.parent_kdn = _nullproof(val.strip())
				elif key.strip() == "best after":
					# FIXME: Convert to date object.
					lic_obj.best_after = _nullproof(val.strip())
				elif key.strip() == "best before":
					# FIXME: Convert to data object.
					lic_obj.best_before = _nullproof(val.strip())
				elif key.strip() == "seat limit":
					lic_obj.lim_seat = int(val.strip())
				elif key.strip() == "seat max":
					lic_obj.max_seat = int(val.strip())
				elif key.strip() == "is reseller":
					lic_obj.is_reseller = bool(val.strip())
		finally:
			if os.path.exists(tf_name):
				os.unlink(tf_name)
	else:
		raise KctlException("No license for KDN %s." % kdn)
	return lic_obj	
	
