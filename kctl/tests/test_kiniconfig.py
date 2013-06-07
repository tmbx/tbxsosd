# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

import sys
# Make sure we test local classes first.
sys.path.insert(0, '.')

import unittest
from kctllib.kiniconfig import *

class KIniConfigTest(unittest.TestCase):
    def test(self):
        config = KIniConfig(override_conf = "tests/test_kiniconfig.ini")
        self.assert_(config.get("section1", "key1") == "value1")
        self.assert_(config.get("section2", "key2") == "value2")
        self.assert_(not config.get("section3", "key3"))

if __name__ == "__main__":
    unittest.main()


