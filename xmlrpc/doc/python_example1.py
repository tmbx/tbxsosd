#!/usr/bin/env python

import sys, os, xmlrpclib

# This is the url for the KPS API.
rpc_url = "https://172.16.100.42:8000/kpsapi.py"

# These are the login and password that are set in the KPS API configuration file.
# This login is in the "org" security context. It is bound to an organization ID (set in the KPS API configuration file).
rpc_login = "client1"
rpc_password = "eeee"

def print_and_return_user(rpc_server, rpc_sid, str_org_id):
    # List current users.
    users_list = rpc_server.list_org_users(rpc_sid, str_org_id)
    print "Current users: %s" % ( str(users_list) ) 
    return users_list

def print_and_return_user_emails(rpc_server, rpc_sid, str_user_id):
    # List current users.
    emails_list = rpc_server.list_user_emails(rpc_sid, str_user_id)
    print "Current emails for user %s: %s" % ( str_user_id, str(emails_list) ) 
    return emails_list

# Connect to the XML RPC server.
print "Connecting to the XML RPC server using url '%s' with login '%s' and password '%s'" % ( rpc_url, rpc_login, rpc_password )
rpc_server = xmlrpclib.ServerProxy(rpc_url)
print "Connected to the XML RPC server."

# Authenticate to the XMLRPC server and get a session ID.
rpc_sid = rpc_server.session_login(rpc_login, rpc_password)
print "Session ID: %s" % ( rpc_sid )

# Get the organization ID user "client1" is bound to.
# org_id is a str_bigint so convert it back to bigint to store locally.
str_org_id = rpc_server.get_security_context_org_id(rpc_sid)
org_id = long(str_org_id)
print "Organization ID: %i" % ( org_id )

# TMP
#rpc_server.remove_user(rpc_sid, 142)

# List current users.
print_and_return_user(rpc_server, rpc_sid, str_org_id)

# Add a user and get its user ID.
# user_id is a str_bigint so convert it back to bigint to store locally.
str_user_id = rpc_server.add_user(rpc_sid, str_org_id, "Foo bar", "foo@bar", "foologin", "foopassword")
user_id = long(str_user_id)
print "Added a user with user_id %i." % ( user_id )

# List emails associated to that user.
print_and_return_user_emails(rpc_server, rpc_sid, str_user_id)

# List current users.
print_and_return_user(rpc_server, rpc_sid, str_org_id)

# Modify user.
rpc_server.modify_user(rpc_sid, str_user_id, "Foo Bar", "foo@bar", "foologin", "fdslj398ggsfd")

# List current users.
print_and_return_user(rpc_server, rpc_sid, str_org_id)

# Add a secondary email to the user.
rpc_server.add_user_email(rpc_sid, str_user_id, "foo2@bar")
print "Added email foo2@bar to user %i." % ( user_id )

# List emails associated to that user.
print_and_return_user_emails(rpc_server, rpc_sid, str_user_id)

# Remove a secondary email to the user.
rpc_server.remove_user_email(rpc_sid, str_user_id, "foo2@bar")
print "Removed email foo2@bar from user %i." % ( user_id )

# List emails associated to that user.
print_and_return_user_emails(rpc_server, rpc_sid, str_user_id)

# Remove the user
rpc_server.remove_user(rpc_sid, user_id);
print "Removed user with user_id %i." % ( user_id )

# List current users.
print_and_return_user(rpc_server, rpc_sid, str_org_id)

