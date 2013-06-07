import sys, unittest

# Make sure we test local classes first.
sys.path.insert(0, ".")

# kpython
from kfile import *

from kctllib.kkeys import *
from kctllib.kparams import *

class TestKey(unittest.TestCase):
    def setUp(self):
        kparams_init()
    
    def testNew(self):       
        sowner = "Test Signature Key"
        (sig_pkey, sig_skey) = Key.newPair(key_type = Key.SIG_PAIR,
                                           key_id = 99,
                                           key_owner = sowner)
        self.assertEqual("99", sig_pkey.id)
        self.assertEqual(sowner, sig_pkey.owner)
        self.assertEqual("sig_pkey", sig_pkey.type)
        self.assertEqual("99", sig_skey.id)
        self.assertEqual(sowner, sig_skey.owner)
        self.assertEqual("sig_skey", sig_skey.type)
        (enc_pkey, enc_skey) = Key.newPair(key_type = Key.ENC_PAIR,
                                           key_id = 99,
                                           key_owner = "Test Encryption Key")

    def testSave(self):
        sowner = "Test Signature Key"
        (sig_pkey1, sig_skey1) = Key.newPair(key_type = Key.SIG_PAIR,
                                             key_id = 99,
                                             key_owner = sowner)
        sig_pkey1.save("/tmp/key1.sig.pkey")
        sig_skey1.save("/tmp/key1.sig.skey")
        sig_pkey2 = Key.fromFile("/tmp/key1.sig.pkey")
        sig_skey2 = Key.fromFile("/tmp/key1.sig.skey")
        self.assertEqual(sig_pkey1.id, sig_pkey2.id)
        self.assertEqual(sig_pkey1.type, sig_pkey2.type)
        self.assertEqual(sig_pkey1.owner, sig_pkey2.owner)
        self.assertEqual(sig_pkey1.key, sig_pkey2.key)

    def testStr(self):
        sig_pkey = Key.fromFile("tests/test_key.sig.pkey")
        self.assertEqual("[key: id=10, owner=Mister Source, type=public signature]", str(sig_pkey))
        enc_skey = Key.fromFile("tests/test_key.enc.skey")
        self.assertEqual("[key: id=10, owner=Mister Source, type=private encryption]", str(enc_skey))

    def testFromFile(self):
        enc_skey = Key.fromFile("tests/test_key.enc.skey")
        self.assertEqual("10", enc_skey.id)
        self.assertEqual("Mister Source", enc_skey.owner)
        self.assertEqual("enc_skey", enc_skey.type)
        sig_pkey = Key.fromFile("tests/test_key.sig.pkey")
        self.assertEqual("10", sig_pkey.id)
        self.assertEqual("Mister Source", sig_pkey.owner)
        self.assertEqual("sig_pkey", sig_pkey.type)

    def testFromBuffer(self):
        enc_skey_data = read_file("tests/test_key.enc.skey")
        enc_skey = Key.fromBuffer(enc_skey_data)
        sig_pkey_data = read_file("tests/test_key.sig.pkey")
        sig_pkey = Key.fromBuffer(sig_pkey_data)

    def testFromStrings(self):
        sig_pkey_id = "10"
        sig_pkey_owner = "Mister Source"
        sig_pkey_data = "AvWVqQAAAAEAAAABAAAAAAAAAAoAAACrKDEwOnB1YmxpYy1rZXkoMzpyc2EoMTpuMTI5OgC+ZB7XBA2ke0jAJ6tc5IETDNZTZNgU2mCQVhtMTJ4MxwhPunyCdGcdO6Dywo39hxkg19v+DE9ZkXFZhuv/nqi0j+1o8iuhiiJMH+AT+AsTVewwrfZbQtvxcSOnEzasK2HrPoawmWARKD9Y8NhSCnffpqVHZupK1Vqb2QtJQVKMHykoMTplMzoBAAEpKSkA"
        sig_pkey = Key.fromStrings(key_id = sig_pkey_id,
                                   key_owner = sig_pkey_owner,
                                   key_type = "sig_pkey",
                                   key_data = sig_pkey_data)

    def testSetKeyName(self):
        sowner = "Test Signature Key"
        nowner = "Test Signature Key Renamed"        
        (sig_pkey, sig_skey) = Key.newPair(key_type = Key.SIG_PAIR,
                                           key_id = 99,
                                           key_owner = sowner)
        sig_pkey.setkeyname(nowner)
        self.assertEqual(nowner, sig_pkey.owner)

    def testSetKeyID(self):
        (sig_pkey, sig_skey) = Key.newPair(key_type = Key.SIG_PAIR,
                                           key_id = 99,
                                           key_owner = "Blarg")
        sig_pkey.setkeyid(100)
        self.assertEqual("100", sig_pkey.id)

if __name__ == "__main__":
    unittest.main()
