# -*- mode: python; python-indent: 4; tab-width: 4; indent-tabs-mode: t; py-indent-offset: 4 -*-

import sys
# Make sure we test local classes first.
sys.path.insert(0, ".")

import unittest
from kctllib.kparams import *
from kctllib.kdatabase import *

class KDatabaseTestProfiles(unittest.TestCase):
    def getProfile(self, id):
        profs = sdb_lsprofiles()
        for prof in profs[1]:
            if prof[1] == id: return prof
        return None     

    def testOrg(self):
        # sdb_addorg
        org_id = sdb_addorg("org.test")

        # sdb_lsorg
        orgs = sdb_lsorg()
        self.assert_([org_id, "org.test", None] in orgs[1])

        # sdb_org_exists
        self.assert_(sdb_org_exists(org_id))

        # sdb_org_check
        sdb_org_check(org_id)

        # sdb_getorgname
        self.assert_(sdb_get_org_name(org_id) == "org.test")

        # sdb_org_id_by_kdn
        self.assert_(sdb_org_id_by_kdn("org.test") == org_id)

        # sdb_kdn_by_org_id
        self.assert_(sdb_kdn_by_org_id(org_id) == "org.test")

        # sdb_setorgforwardto
        sdb_setorgforwardto(org_id, "blarg@blarg")       
        orgs = sdb_lsorg()
        self.assert_([org_id, "org.test", "blarg@blarg"] in orgs[1])

        # sdb_rmorg
        sdb_rmorg(org_id)
        orgs = sdb_lsorg()
        for org in orgs[1]: self.assert_(org[0] != org_id)

    def testUserProfiles(self):
        org_id = sdb_addorg("org.test")

        # sdb_adduser
        prof_id = sdb_adduser(org_id, "First", "Last")

        # sdb_lsprofiles
        profs = sdb_lsprofiles()
        prof = self.getProfile(prof_id)
        self.assert_(prof)
        self.assert_(prof[0] == org_id)
        self.assert_(prof[1] == prof_id)
        self.assert_(prof[2] == "User")
        self.assert_(prof[4] == "First Last")

        # sdb_setkey
        sdb_setkey(prof_id, '20')
        prof = self.getProfile(prof_id)
        self.assert_(prof[3] == '20')

        # sdb_disownkey
        sdb_disownkey(prof_id)
        prof = self.getProfile(prof_id)
        self.assert_(prof[3] == 'No key')

        # sdb_getprofileorg
        self.assert_(sdb_getprofileorg(prof_id) == org_id)

        # sdb_getprofilename
        self.assert_(sdb_get_prof_name(prof_id) == "First Last")

        # sdb_profiles_find
        self.assert_(sdb_profiles_find())

        # sdb_profile_find
        prof_data = sdb_profile_find(prof_id)
        self.assert_(prof_data)
        user_id = prof_data['user_id']

        # sdb_user_profile_valid
        self.assert_(sdb_user_profile_valid(user_id))

        # sdb_get_org_status
        self.assert_(sdb_getprofstatus(prof_id) == 0)

        # sdb_rmprofile
        sdb_rmprofile(prof_id)
        self.assert_(not self.getProfile(prof_id))

        sdb_rmorg(org_id)

    def testLDAPGroupProfiles(self):
        org_id = sdb_addorg("org.test")

        # sdb_addgroup
        prof_id = sdb_addgroup(org_id, "Test Group")
        prof_data = sdb_profile_find(prof_id)
        group_id = prof_data['group_id']
        self.assert_(prof_id)
        self.assert_(prof_data['prof_type'] == 'G')
        self.assert_(prof_data['group_id'])

        # sdb_addldapgroup
        ldap_group_id = sdb_addldapgroup(group_id, "DN=blarg,DC=blorg")

        # sdb_lsldapgroups
        groups = sdb_lsldapgroups(group_id)
        self.assert_(groups[1])
        self.assert_(groups[1][0][1] == "DN=blarg,DC=blorg")

        # sdb_group_profile_valid
        self.assert_(sdb_group_profile_valid(group_id))

        # sdb_rmldapgroup
        sdb_rmldapgroup(ldap_group_id)
        groups = sdb_lsldapgroups(group_id)
        self.assert_(not groups[1])
                
        sdb_rmprofile(prof_id)
        sdb_rmorg(org_id)

    def testUserEmail(self):
        org_id = sdb_addorg("org.test")
        prof_id = sdb_adduser(org_id, "First", "Last")

        # sdb_addpemail
        sdb_addpemail(prof_id, "blarg@blarg")

        # sdb_lsemail
        emails = sdb_lsemail(prof_id)
        self.assert_(["blarg@blarg *"] in emails[1])

        # sdb_addemail
        sdb_addemail(prof_id, "blarg@blarg2")
        emails = sdb_lsemail(prof_id)
        self.assert_(["blarg@blarg2"] in emails[1])

        # sdb_email_primary_find
        prof_data = sdb_profile_find(prof_id)
        user_id = prof_data['user_id']
        self.assert_(sdb_email_primary_find(user_id)[0]['email_address'] == "blarg@blarg")

        # sdb_rmemail
        sdb_rmemail(prof_id, "blarg@blarg2")
        emails = sdb_lsemail(prof_id)
        self.assert_(not ["blarg@blarg2 *"] in emails[1])

        sdb_rmprofile(prof_id)
        sdb_rmorg(org_id)      

class KDatabaseTestKeys(unittest.TestCase):                      
    def testKey(self):
        sdb_importpubkey('enc', 99, "Test Key", "TEST KEY - ENCRYPTION SECRET KEY")
        sdb_importpubkey('sig', 99, "Test Key", "TEST KEY - SIGNATURE PRIVATE KEY")
        sdb_importprivkey('sig', 99, "Test Key", "TEST KEY - ENCRYPTION SECRET KEY")
        sdb_importprivkey('enc', 99, "Test Key", "TEST KEY - SIGNATURE SECRET KEY")

        # sdb_get*key
        self.assert_(sdb_getpubkey('enc', 99))
        self.assert_(sdb_getprivkey('enc', 99))
        self.assert_(sdb_getpubkey('sig', 99))
        self.assert_(sdb_getprivkey('sig', 99))

        # sdb_lskeys
        self.assert_(sdb_lskeys())

        # sdb_key_valid
        self.assert_(sdb_key_valid(99))

        # sdb_getkeystatus
        #self.assert_(sdb_getkeystatus(99) == 0)

        # sdb_setkeystatus
        #sdb_setkeystatus(99, 1)
        #self.assert_(sdb_getkeystatus(99) == 1)

        # sdb_*keyexists
        self.assert_(sdb_privkeyexists(99))
        self.assert_(sdb_pubkeyexists(99))
        self.assert_(not sdb_privkeyexists(100))

        # sdb_del*keys
        sdb_delprivkeys(99)
        sdb_delpubkeys(99)

class KDatabaseTestLogin(unittest.TestCase):
    def testLogin(self):
        # sdb_addlogin
        sdb_addlogin(9999, 9999, "mathieu", "hahahaha")

        # sdb_lslogin
        logins = sdb_lslogin()
        self.assert_([9999L, 'mathieu', 'hahahaha'] in logins[1])

        # sdb_logins_find
        self.assert_(sdb_logins_find())

        # sdb_login_find
        self.assert_(sdb_login_find(9999))

        # sdb_login_find_by_login
        self.assert_(sdb_login_find_by_login('mathieu'))

        # sdb_rmlogin
        sdb_rmlogin("mathieu")
        logins = sdb_lslogin()
        self.assert_(not [9999L, 'mathieu', 'hahahaha'] in logins[1])
        self.assert_(not sdb_login_find(9999))
        self.assert_(not sdb_login_find_by_login('mathieu'))

if __name__ == "__main__":
    db_init()
    kparams_set("commit", True)
    unittest.main()
