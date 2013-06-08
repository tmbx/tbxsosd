# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

from kctllib.kparams import *

# kpython
from krun import *
from kout import *

def scriptable_out(s):
    if kparams_get("scriptable"):
        out(s)

# will be used later for quoting
# note: I think some people (Laurent at least) are parsing output strings
# until we're not sure people are all using the scriptable option for getting data out of kctl, we should not change strings
def aaa(s):
    return s

# return a string version... could be used differently later
def bbb(s):
    return str(s)

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

def get_license_item(p_org_id, item):
    import re
    kdn = sdb_kdn_by_org_id(p_org_id)
    kctlbin = kparams_get("kctlbin")
    cmd = [kctlbin, "showlicense", kdn]
    proc = KPopen("", cmd) # "" is data sent to stdin
    if proc.return_code == 0:
        for line in proc.stdout.split("\n"):
            try:
                return re.match("^%s: (-?[0-9]+)$" % (item), line).group(1)
            except:
                pass
    return None

# non recursive... good only with for a single reseller
def get_seats_available_to_allocate(p_org_id, org_id):
    parent_license_number = get_license_item(p_org_id, "seat limit")
    #debug("parent license limit: %s" % str(parent_license_number))
    reseller_allocated_seats = sdb_reseller_allocated_seats(p_org_id)
    #debug("total alloc: %s" % str(reseller_allocated_seats))
    try:
        allocated_seats = sdb_allocated_seats(org_id)
    except:
        allocated_seats = 0
    #debug("alloc: %s" % (str(allocated_seats)))
    available = int(parent_license_number) - (int(reseller_allocated_seats) - int(allocated_seats))
    #debug("available: %s" % ( str(available) ))
    return int(available)

def print_tabbed_results(field_descs, res):
    # print headers (field_descs)
    if field_descs != None and res != None:
        for field_desc in field_descs:
            out_raw("%s\t" % field_desc[0]) # field_desc[0] --> field name
        out("")

        for row in res:
            for field_value in row:
                out_raw("%s\t" % field_value)
            out("")

def askpassword():
    pw = None
    while pw == None or pw == "":
        pw = input_prompt("User password:")
    return pw

# This function prompts the user for a string. It returns the string entered,
# which can be "".
def input_prompt(prompt):
        try:
                return raw_input(prompt + " ")

        except Exception:
                out("")
                raise KeyboardInterrupt
