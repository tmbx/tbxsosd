# -*- mode: python; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

import sys
# Make sure we test local classes first.
sys.path.insert(0, '.')

import unittest
from kctllib.ktbxsosdconfig import *

class KTbxsosdConfigTest(unittest.TestCase):
    def test(self):
        config = KTbxsosdConfig(source_file = "tests/test_ktbxsosdconfig.conf")
        self.assert_(config.get("test.item1") == "value1")
        self.assert_(config.get("test.item2") == "value2")
        self.assert_(not config.get("test.item3"))
        config.set("test.item3", "value3")
        self.assert_(config.get("test.item3") == "value3")
        config.save(target_file = "/tmp/ktbxsosdconfig_test.conf")

        config = KTbxsosdConfig(source_file = "tests/test_ktbxsosdconfig.conf",
                                  user_file = "/tmp/ktbxsosdconfig_test.conf")
        self.assert_(config.get("test.item1") == "value1")
        self.assert_(config.get("test.item2") == "value2")
        self.assert_(config.get("test.item3") == "value3")

if __name__ == "__main__":
    unittest.main()


