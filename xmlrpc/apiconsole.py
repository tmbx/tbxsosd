#!/usr/bin/python

import sys, xmlrpclib

# kpython
from kreadline import *
from kbase import PropStore

# Blatantly copied from kctl.
def print_tabbed_results(field_descs, res):
    # print headers (field_descs)
    if field_descs != None and res != None:
        for field_desc in field_descs:
            sys.stdout.write("%s\t" % field_desc[0]) # field_desc[0] --> field name
        sys.stdout.write("\n")

        for row in res:
            for field_value in row:
                sys.stdout.write("%s\t" % field_value)
            sys.stdout.write("\n")

class CallCommand(Command):
    Name = "call"
    Help = "Call an KPS API command."
    Syntax = "<command> [<parameters>]*"
    MaxParams = None
    MinParams = 1

    def run(self, interpreter, command, *args):
        server = interpreter.server
        server_sid = interpreter.server_sid

        method = server.__getattr__(command)

        try:
            print [command, server_sid] + list(args)

            ret = apply(method, [server_sid] + list(args))

            if type(ret) is str:
                success_ret = [1]
                failure_ret = [0]

                if ret in success_ret: print "Command succeeded."
                elif ret in failure_ret: print "Command failed."
                else: print "Command returned: %s" % ret            
            else:
                if type(ret[0]) is list:
                    print_tabbed_results(ret[0], ret[1])
                else:
                    for c in ret: print c

        except xmlrpclib.Fault, ex:
            #print "Command failed: %s" % ex.faultString
            raise ex

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.stderr.write("Syntax: apiconsole [URL] [username] [password]\n")
        sys.exit(1)
    
    url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    server = xmlrpclib.ServerProxy(url)
    server_sid = server.session_login(username, password)

    intr = CommandInterpreter([CallCommand()], "KPS> ")
    intr.server = server
    intr.server_sid = server_sid
    intr.loop()

    sys.exit(0)
