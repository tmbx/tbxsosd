# -*- encoding: utf-8 -*-
# ktbxsosdconfigdaemon.py --- Tbxsosd Config Daemon client interface.
# Copyright (C) 2006, 2007, 2008 Teambox inc.  All rights reserved.

# Author: François-Denis Gonthier <fdgonthier@teambox.co>

import os, os.path, socket
from kexcept import *

class TbxsosdConfigDaemon:  

    def __init__(self):
        self.socket_path = "/tmp/tbsos-configd-cmd"

    def present(self):
        return os.path.exists(self.socket_path)

    def _write_and_expect(self, write_what, expect_what):
        if not self.present():            
            raise KctlException("tbxsosd-configd socket doesn't exists.")

        # Connect to the socket.
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.connect(self.socket_path)
        except Exception, ex:
            raise KctlException("Failed to connect to tbxsosd-configd: %s", str(ex))

        is_ok = False
        try:
            sock_file = self.socket.makefile()
            sock_file.write(write_what)
            sock_file.flush()
            line = sock_file.readline()
            if line.strip() == expect_what.strip():
                is_ok = True
        except Exception, ex:
            raise KctlException("Failed to write command to tbxsosd-config: %s" % str(ex))
        finally:
            if self.socket:
                self.socket.close()

        return is_ok
        
    def reboot(self):
        return self._write_and_expect("reboot\n", "ok")

    def restart(self):
        return self._write_and_expect("rehash\n", "ok")        

    def set_date(self, year, month, day):
        fyear = "%04d" % int(year)
        fmonth = "%02d" % int(month)
        fday = "%02d" % int(day)        
        return self._write_and_expect("date\n%s\n%s\n%s\n" % (fyear, fmonth, fday), "ok")

    def set_time(self, hour, min, sec):
        fhour = "%02d" % int(hour)
        fmin = "%02d" % int(min)
        fsec = "%02d" % int(sec)        
        return self._write_and_expect("time\n%s\n%s\n%s\n" % (fhour, fmin, fsec), "ok")

    def update_bundle(self, bundle_file):
        return self._write_and_expect("bundle_update\n%s\n" % bundle_file, "ok")

    def install_bundle(self, bundle_file):
        return self._write_and_expect("bundle_install\n%s\n" % bundle_file, "ok")

    def switch_ssl_keys(self, key_file, cert_file):
        return self._write_and_expect("ssl_key_switch\n%s\n%s\n" % (key_file, cert_file), "ok")

    def postfix_relayhost(self, relay):
        return self._write_and_expect("postfix_relayhost\n%s\n" % relay, "ok")
