#!/usr/bin/env python
# -*- mode: python; python-indent-tabs-mode: t; python-indent-level: 4; tab-width: 4 -*-

###
### manual tests for xmlrpc api
###

import sys, os, xmlrpclib

# from kpython
import kdebug


class ExceptionReturn(Exception):
    def __init__(self, ret, message):
        self.return_value = ret
        self.message = message

def assert_fault_xmlrpc(func_name, fault_codes, *params):
    try:
        value = getattr(server, func_name)(*params)
        raise ExceptionReturn(value,
            "ERROR: func: '%s', params:'%s': succeded.. shoud have failed with code(s) %s" % \
            ( str(func_name), str(*params), str(fault_codes) ) )

    except xmlrpclib.Fault, e:
        if (type(fault_codes) == int and fault_codes != e.faultCode) or \
                (type(fault_codes) != int and not e.faultCode in fault_codes):
            raise Exception(
                "ERROR: func: '%s', params: '%s': expected fault(s) '%s', got fault %i, string '%s'." % \
                ( str(func_name), str(params), str(fault_codes), e.faultCode, e.faultString) )

    kdebug.debug(1, 
        "Suceeded: func '%s', params '%s': failed like expected with one of code(s) '%s'." \
            % ( str(func_name), str(params), str(fault_codes) ) )

def connect(url):
    global server

    try:
        kdebug.debug(2, "Connecting to url '%s'." % ( url ) )
        server = xmlrpclib.ServerProxy(url)
        kdebug.debug(1, "Connected to url '%s'." % ( url ) )
        
    except xmlrpclib.ProtocolError, e:
        print "A protocol error occurred:"
        print "URL: %s" % e.url
        print "HTTP/HTTPS headers: %s" % e.headers
        print "Error code: %d" % e.errcode
        print "Error message: %s" % e.errmsg
        sys.exit(1)

def authenticate():
    global server_sid

    kdebug.debug(3, "Authenticating with user '%s', password '%s'." % ( server_login, server_password ) )
    server_sid = server.session_login(server_login, server_password)
    kdebug.debug(2, "Session ID: %s" % ( server_sid ))

def test_bad_functions():
    pass
#kdebug.debug(1, "TEST_BAD_FUNCTIONS")
#    assert_fault_xmlrpc(server._dispatch, 103)
#    kdebug.debug(1, "///TEST_BAD_FUNCTIONS")

def test_bad_nb_arguments():
    assert_fault_xmlrpc("session_login", 104)
    assert_fault_xmlrpc("get_security_context", 104)
    assert_fault_xmlrpc("get_security_context_org_id", 104)
    # FIXME FOR DEV ONLY
    assert_fault_xmlrpc("get_main_key_id", 104)
    assert_fault_xmlrpc("get_key_id", 104)
    # /FIXME
    assert_fault_xmlrpc("add_user", 104)
    assert_fault_xmlrpc("modify_user", 104)
    assert_fault_xmlrpc("remove_user", 104)
    assert_fault_xmlrpc("list_org_users", 104)
    assert_fault_xmlrpc("add_user_email", 104)
    assert_fault_xmlrpc("remove_user_email", 104)
    assert_fault_xmlrpc("list_user_emails", 104)

def test_bad_arguments():

    # Test bad ID faults.
    for bad_id in bad_bigints:
        # org id
        assert_fault_xmlrpc("add_user", [121,122,123,126], server_sid, 
            bad_id, "name", "email", "login", "pass")
        assert_fault_xmlrpc("list_org_users", [121,122,123,126], server_sid, 
            bad_id)

        # user id
        assert_fault_xmlrpc("modify_user", [121,122,123,126], server_sid, 
            bad_id, "name", "email", "login", "pass")
        assert_fault_xmlrpc("remove_user", [121,122,123,126], server_sid, 
            bad_id)
        assert_fault_xmlrpc("add_user_email", [121,122,123,126], server_sid, 
            bad_id, "email")
        assert_fault_xmlrpc("remove_user_email", [121,122,123,126], server_sid, 
            bad_id, "email")
        assert_fault_xmlrpc("list_user_emails", [121,122,123,126], server_sid, 
            bad_id)
 
    # Test bad non-empty strings.
    for bad_non_empty_string in bad_non_empty_strings:
        # Test server_sid only once.. even though it is used in almost all 
        # functions.
        assert_fault_xmlrpc("get_security_context", [121,122,123,126], 
            bad_non_empty_string)

        assert_fault_xmlrpc("session_login", [121,122,123,126], 
            bad_non_empty_string, "password")
        assert_fault_xmlrpc("session_login", [121,122,123,126], "login", 
            bad_non_empty_string)
        assert_fault_xmlrpc("add_user", [121,122,123,126], server_sid, 99999, 
            bad_non_empty_string, "email", "login", "password")
        assert_fault_xmlrpc("add_user", [121,122,123,126], server_sid, 99999, 
            "name", bad_non_empty_string, "login", "password")
        assert_fault_xmlrpc("add_user", [121,122,123,126], server_sid, 99999, 
            "name", "email", bad_non_empty_string, "password")
        assert_fault_xmlrpc("add_user", [121,122,123,126], server_sid, 99999, 
            "name", "email", "login", bad_non_empty_string)
        assert_fault_xmlrpc("modify_user", [121,122,123,126], server_sid, 
            99999, bad_non_empty_string, "email", "login", "password")
        assert_fault_xmlrpc("modify_user", [121,122,123,126], server_sid, 
            99999, "name", bad_non_empty_string, "login", "password")
        assert_fault_xmlrpc("modify_user", [121,122,123,126], server_sid, 
            99999, "name", "email", bad_non_empty_string, "password")
        assert_fault_xmlrpc("modify_user", [121,122,123,126], server_sid, 
            99999, "name", "email", "login", bad_non_empty_string)
        assert_fault_xmlrpc("add_user_email", [121,122,123,126], server_sid, 
            99999, bad_non_empty_string)
        assert_fault_xmlrpc("remove_user_email", [121,122,123,126], server_sid,
            99999, bad_non_empty_string)


def test_common1():
    # Test login faults.
    assert_fault_xmlrpc("session_login", 201, "gfsdgjdfgdg", "dfgdgdgdg")
    assert_fault_xmlrpc("session_login", 201, "fsgdfgdfgdfgdf", server_password)
    assert_fault_xmlrpc("session_login", 201, server_login, "FSGDFGDFGdfgfdg")

    # Test invalid session fault.
    assert_fault_xmlrpc("get_security_context", 131, "FSGDFGDFGdfgfdg")

    # ........
    # No exceptions to check for those function.
    #get_security_context:
    #get_security_context_org_id:
    #get_main_key_id
    #get_key_id

    # Testing bad user fault.
#    assert_fault_xmlrpc("modify_user", [121,122,123,126], server_sid, 99999, "bad_user_id", "name", "login", "pass")
#    assert_fault_xmlrpc("add_user", 241, server_sid, "bad_org_id", "Test", "login", "pass")
#    assert_fault_xmlrpc("remove_user", [121,122,123,126], server_sid, 99999999)
#    assert_fault_xmlrpc("list_org_users", [121,122,123,126], server_sid, 99999999)
#    assert_fault_xmlrpc("add_user_email", [121,122,123,126], server_sid, "gfsdgfdgdf", "allo@bye")
    
class User:
    def __init__(self, full_name=None, email=None, login=None, password=None):
        self.full_name = full_name
        self.email = email
        self.login = login
        self.password = password

    def from_dict(self, d):
        u = User()
        u.full_name = d["full_name"]
        u.email = d["email"]
        u.login = d["login"]
        u.password = d["password"]
        return u

    def __cmp__(self, other):
        # FIXME: Don't check secondary emails right now.
        if self.full_name == other.full_name and \
            self.email == other.email and \
            self.login == other.login and \
            self.password == other.password:
            return True
        return False

    def __str__(self):
        return "<User full_name='%s' email='%s' login='%s' password='%s'>" % \
            ( str(self.full_name), str(self.email), str(self.login), str(self.password) )

    def to_list(self):
        return [self.full_name, self.email, self.login, self.password]

class Users:
    def __init__(self):
        self.users = {}

    def add_user(self, user):
        user.parent = self
        self.users[user.id] = user
    
    def from_list(self, user_list):
        users = Users()
        for u in user_list:
            user = User().from_dict(u)
            users.add_user(user)
        return users

    def __cmp__(self, other):
        # FIXME: Don't check secondary emails right now.
        if self.users.keys().sort() != other.users.keys().sort():
            return False
        for id in self.users.keys():
            if self.users[id] != other.users[id]:
                return False
        return True

    #def bad_logins(self):
    #    logins = []
    #    for user in self.users:
    #        logins.append(user.login)
    #    return logins

def add_bad_user(*params):
    try:
        assert_fault_xmlrpc("add_user", 103, *params)
        print "Test passed: 'add_bad_users, %s'" % ( str(params) )
    except ExceptionReturn, er:
        print er.message
        try:
            server.remove_user(params[0], er.return_value)
        except Exception, e:
            print "Exception while cleaning bad user: %s" % ( str(e) )

def test_add_user(*params):
    try:
        server.add_user(*params)
    except xmlrpclib.Fault, e:
        print "ERROR: Fault: %i: '%s'" % ( e.faultCode, e.faultString )

def test_list_users(org_id):
    print "Users list: " + str(server.list_org_users(server_sid, org_id))

def test_list_emails(user_id):
    emails_list = server.list_user_emails(server_sid, user_id)
    print "Emails list for user '%s': %s." % ( str(user_id), str(emails_list) )

def test_common2():

    org_id = server_org_id

    print "Adding a user..."
    full_name = "aaa bbb ccc"
    email = "fff@fff"
    login = "apitest1"
    password = "aaaa"
    user_id = server.add_user(server_sid, str(org_id), full_name, email, login, password)
    print "Added user '%s'." % ( str(user_id) )
    test_list_users(org_id)
    test_list_emails(user_id)
    print
    print

    print "Deleting user..."
    server.remove_user(server_sid, user_id)
    test_list_users(org_id)
    print
    print
    print
    print


    print "Adding a user..."
    full_name = "aaa"
    email = "fff@fff"
    login = "apitest1"
    password = "aaaa"
    user_id = server.add_user(server_sid, str(org_id), full_name, email, login, password)
    print "Added user '%s'." % ( str(user_id) )
    test_list_users(org_id)
    test_list_emails(user_id)
    print
    print

    try:
        print "Modifiying user..."
        server.modify_user(server_sid, str(user_id), full_name, email, login, password)
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print

        print "Modifiying user..."
        full_name = "Atchoum"
        email = "foo@bar"
        login = "apitest2"
        password = "bbbbbbb"
        server.modify_user(server_sid, str(user_id), full_name, email, login, password)
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print

        print "Modifiying user..."
        full_name = "aaaa bbbb "
        server.modify_user(server_sid, str(user_id), full_name, email, login, password)
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print


        print "Adding an email..."
        new_email = "junk1@org1"
        server.add_user_email(server_sid, str(user_id), new_email)
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print

        print "Adding an email..."
        new_email = "junk2@org2"
        server.add_user_email(server_sid, str(user_id), new_email)
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print


        print "Adding an email..."
        new_email = "junk1@org1"
        try:
            server.add_user_email(server_sid, str(user_id), new_email)
            raise Exception("ERROR: Should not have been able to add this email.")
        except xmlrpclib.Fault, e:
            if int(e.faultCode) != 292: raise e
            print "Failed like expected."
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print

        print "Removing an email..."
        email = "foo@barsdfsdfsdfsdfsdf"
        try:
            server.remove_user_email(server_sid, str(user_id), email)
            raise Exception("ERROR: Should not have been able to delete this email.")
        except xmlrpclib.Fault, e:
            if e.faultCode != 291: raise e
            print "Failed like expected."
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print


        print "Removing an email..."
        email = "foo@bar"
        try:
            server.remove_user_email(server_sid, str(user_id), email)
            raise Exception("ERROR: Should not have been able to delete this email.")
        except xmlrpclib.Fault, e:
            if e.faultCode != 296: raise e
            print "Failed like expected."
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print


        print "Removing an email..."
        email = "junk1@org1"
        server.remove_user_email(server_sid, str(user_id), email)
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print

        print "Removing an email..."
        email = "junk2@org2"
        server.remove_user_email(server_sid, str(user_id), email)
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print

        print "Removing an email..."
        email = "junk2@org2"
        try:
            server.remove_user_email(server_sid, str(user_id), email)
            raise Exception("ERROR: Should not have been able to delete this email.")
        except xmlrpclib.Fault, e:
            if e.faultCode != 291: raise e
            print "Failed like expected."
        test_list_users(org_id)
        test_list_emails(user_id)
        print
        print


    except Exception, e:
        server.remove_user(server_sid, str(user_id))
        test_list_users(org_id)
        print "Removed user because there was an exception while modifying user..."
        raise e


    print "Deleting user..."
    server.remove_user(server_sid, str(user_id))
    test_list_users(org_id)
    print
    print

#    i_users = Users()
#    r_users = Users()
#
#    i_users = []
#    i_user_ids = []
#    r_users = []
#    r_
#    for i in range(4):
#        i_user = User(good_names[i], good_emails[i], good_logins[i], good_passwords[i])
#        i_users.append(user)
#        user_id = server.add_user, server_sid, server_org_id, user.to_list())
#        i_user_ids[i] = user_id
#        try:
#            rpc_users_list = server.list_users(server_sid, server_org_id)
#            for rpc_user_dict in rpc_users_list:
#                rpc_user = User()
#                rpc_user.from_dict(user)
#db_user = ...
#                         assert ....
#
#
#        server.remove_user(server_sid, user_id)

# FIXME: FOR DEV ONLY! TODO: REMOVE!
def test_keys():
    main_key_id = server.get_main_key_id(server_sid)
    assert str(main_key_id).isdigit()
    kdebug.debug(3, "Main key ID: %s" % ( main_key_id ))

    key_id = server.get_key_id(server_sid)
    assert str(key_id).isdigit()
    kdebug.debug(3, "Key ID: %s" % ( key_id ))

def test_admin():
    global server_org_id

    assert_fault_xmlrpc("get_security_context_org_id", 131, server_sid)

    server_org_id = default_org_id

def test_org():
    global server_org_id

    server_org_id = server.get_security_context_org_id(server_sid)
    assert str(server_org_id).isdigit()
    kdebug.debug(2, "Bound to organization ID: %s" % ( str(server_org_id) ))

def tests():
    # FIXME: FOR DEV ONLY! TODO: REMOVE!
    test_keys()

    # Do function calling tests.
    test_bad_functions()
    test_bad_nb_arguments()
    test_bad_arguments()

    # Do per security context tests.
    sec_ctx = server.get_security_context(server_sid)
    if sec_ctx == "admin":
        test_admin()
    elif sec_ctx == "org":
        test_org()
    else:
        raise Exception("Unknown security context...")

    # Do common tests.
    test_common1()
    test_common2()



bad_bigints = [ "", -1, " ", "invalid_id" ]
bad_non_empty_strings = [ "", "    " ]

default_org_id = 1

#good_names = [ " a", " b", "c", " dd", "ee ", " ee ", " ff ff", "gg gg ", " hh hh ", "ii ii ii", "jj jj jj jj" ]
#good_logins = [ "a", " b", "c ", " aa ", "bb" "cc" ] 
#good_passwords = good_logins
#good_emails = [ "a@b.com", " a@c.com", "a@d.com ", "a@e.com" ]

server = None
server_sid = None

def main():
    global server_login
    global server_password

    kdebug.set_debug_level(9)

    if len(sys.argv) < 3:
        sys.stderr.write("Syntax: apiconsole <URL> <username> <password>\n")
        sys.exit(1)

    url = sys.argv[1]
    server_login = sys.argv[2]
    server_password = sys.argv[3]

    connect(url)

    authenticate()

    tests()

if __name__ == "__main__":
    main()

