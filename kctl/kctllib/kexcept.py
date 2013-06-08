# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

# kpython
from kout import *

class KctlCommandError(Exception):	
	def __init__(self, err_msg):		
		self.err_msg=err_msg
		
	def __str__(self):
		return repr(self.err_msg)

class KctlException(Exception):
	pass
