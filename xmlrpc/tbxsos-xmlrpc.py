#!/usr/bin/env python

###
### kps xmlrpc api server
###

# If you want this to work during development, do the following links.
#  /var/www/kpsapi/kpsapi.py -> $PWD/kpsapi.py

# standard python stuff
import logging, logging.config, os, sys, xmlrpclib, re, \
    time, datetime, pickle, md5, base64, \
    glob, socket, stat, ConfigParser, string, traceback
from SimpleXMLRPCServer import CGIXMLRPCRequestHandler

# from kpython
import kbase
#import kcd_client
# from kweb
import kweb_session
from config import *

# from kas-python
from kcd_lib import get_master_config, get_kcd_external_conf_object

# from kctllib
from kctllib.kdatabase import *
from kctllib.kkeys import Key

# Main logger
log = None

# session database
sess_database='tbxsos_xmlrpc'

# config file path
ini_conf_path = os.path.join(CONF_DIR, "tbxsos-xmlrpc.ini")

# main key path
#main_priv_enc_key_path = "/etc/teambox/act/keys/main/email.enc.pkey"

# KCD external configuration
master_config = None
kcd_external_conf = None

# tbxsosd-config daemon socket
TBXSOSD_CONFIGD_SOCKET="/tmp/tbxsosd-configd-cmd"
if os.environ.has_key("TBXSOSD_CONFIGD_SOCKET"):
    TBXSOSD_CONFIGD_SOCKET=os.environ["TBXSOSD_CONFIGD_SOCKET"]

# Security contexts definition
KAPI_SECURITY_CTX_ADMIN="admin"
KAPI_SECURITY_CTX_ORG="org"
valid_security_contexts = [ KAPI_SECURITY_CTX_ADMIN, KAPI_SECURITY_CTX_ORG ]

# This function returns True / False if the script is run in development / 
# production mode respectively.
def is_in_debug():
    return True

# This class adds a method to ConfigParser.
class CustomConfigParser(ConfigParser.ConfigParser):
    def get_default(self, section, option, default_value):
        try:
            return self.get(section, option)
        except ConfigParser.NoOptionError, e:
            return default_value

import kanp
import kpg
from kcd_lib import get_kcd_db_conn
# TODO import FreemiumKcdClient from the correct place
class FreemiumKcdClient:
    # Constructor
    # parameters:
    #  conf: configuration object, or None
    def __init__(self, conf, db_conn=None):
        # Get config object.
        self.conf = conf

        # Get db connection if provited.
        self.db_conn = db_conn

        # Command ID.
        self.command_id = 0

        # Initialize parent class, but do not connect.
        #tcp_client.TcpClient.__init__(self, kcd_external_conf.kcd_host, kcd_external_conf.kcd_port, use_openssl=True, allow_dh=True)

    # This method connects or reuse a DB connection to KCD.
    def db_connect(self):
        if not self.db_conn: self.db_conn = get_kcd_db_conn(self.conf)

    def set_freemium_user(self, email, license):
        # Connect to database if needed.
        self.db_connect()

        # Build ANP arguments list.
        m = kanp.ANP_msg()
        m.add_str(email)
        m.add_str(license)

        # Do the query.
        query = "SELECT set_freemium_user('%s')" % ( pgdb.escape_bytea(m.get_payload()) )
        cur = kpg.exec_pg_query_rb_on_except(self.db_conn, query)
        row = cur.fetchone()
        self.db_conn.commit()

        return 0

# Load session and run some checks.
def session_load(sid):
    validate_non_empty_string(sid)
    try:
        # Load session.
        session = kweb_session.ksession_get_session(sid, database=sess_database)
    except Exception, e:
        log.error("Session error: '%s'." % ( str(e) ) )
        raise xmlrpclib.Fault(101, "Internal error (" + str(e) + ").")

    if sid != session.sid or session.data["kpsapi"] != 1:
        # Invalid session.
        raise xmlrpclib.Fault(131, "Invalid session ID.")

    return session

# Check if security context allows this action.
def session_security_context_check(session, security_context):
    if security_context != session.data["security_ctx"]:
        # Security context does not allow this call.
        raise xmlrpclib.Fault(141, "Your security context does not allow this.")

# This function splits a full name in two parts.
def full_name_split(name):
    arr = name.split(" ", 1)
    if len(arr) == 1: return [name, ""]
    return arr

# This function converts an int or bigint to a string.
# Cause: xmlrpc does not support bigints!
# This is used only for easy tracking of where bigint values are converted.
def bigint_to_str(i):
    return str(i)

# This function gets an organization by its organization ID.
def get_org_by_org_id(org_id):
    row = sdb_get_org_by_org_id(org_id)
    if not row: raise xmlrpclib.Fault(241, "This organization does not exist.")
    return row

# This function gets an organization by profile ID.
def get_org_by_profile_id(prof_id):
    row = sdb_profile_find(prof_id)
    if not row: raise xmlrpclib.Fault(271, "This user does not exist.")
    org_id = row["org_id"]
    return get_org_by_org_id(org_id)

# This function gets a user by user ID.
def get_user_by_user_id(user_id):
    row = sdb_user_profile_find_by_user_id(user_id)
    if not row:
        raise xmlrpclib.Fault(271, "This user does not exist.")
    return row

# This function gets a login row by login.
def get_login_row_by_login(login):
    row = sdb_login_find_by_login(login)
    if not row:
        raise xmlrpclib.Fault(281, "This login does not exist.")

# Gets kps user id from the login  
def get_user_id_from_login(login):
    user_login = sdb_login_find_by_login(login)
    if not user_login:
        return None		
    user_profile = sdb_user_profile_find_by_prof_id(user_login["prof_id"])
    user_id = user_profile["user_id"]
    return bigint_to_str(user_id)
    pass


# This function checks that org_id is editable by user.
def security_ctx_check_org(session, org_id):
    if session.data["security_ctx"] == KAPI_SECURITY_CTX_ORG and str(org_id) != str(session.data["org_id"]):
        log.warning("User is bound to organization ID '%s' but tried to access organization ID '%s'." % \
            ( str(session.data["org_id"]), str(org_id) ) )
        raise xmlrpclib.Fault(141, "Security context does not allows this.")

# Validate items.
def validate_str_bigint(i):
    if not i or not str(i).isdigit():
        raise xmlrpclib.Fault(126, "Excepting an integer or a numeric string.")
    return int(i)

def validate_non_empty_string(s, max_length=None):
    if not s: raise xmlrpclib.Fault(121, "Invalid parameter: null values not supported.")
    s = s.strip(" ")
    if s == "": raise xmlrpclib.Fault(122, "Invalid parameter: empty string.")
    if max_length:
        if len(s) > max_length:
            raise xmlrpclib.Fault(123, "Invalid parameter: string too long.")
    return s

def validate_org_id(org_id):
    return validate_str_bigint(org_id)

def validate_user_id(user_id):
    return validate_str_bigint(user_id)

def validate_login(login):
    return validate_non_empty_string(login, 50) # 320

def validate_password(password):
    return validate_non_empty_string(password, 50)

def validate_full_name(full_name):
    return validate_non_empty_string(full_name, 200)

def validate_email(email):
    return validate_non_empty_string(email, 200) # 320

def convert_pg_timestamp_to_epoch(ts):
    return int(time.mktime(datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f").timetuple()))

# Methods available to the client
class KPSApi:
    def test_int(self):
        return 123

    def test_str(self):
        return "hello world!"

    def test_array(self):
        return [ "aa", "bb", "cc" ]

    def test_dict(self):
        return { "aa" : "aaaa", "bb" : "bbbb", "cc" : "cccc" }

    # Login. 
    # Returns: (string) session id
    def session_login(self, login, password):
        # Initialize the database (kctl).
        db_init()

        # Validate parameters.
        login = validate_login(login)
        password = validate_password(password)

        # Load config
        config = CustomConfigParser()
        config.read(ini_conf_path)

        # Check login/pass pair.
        if not config.has_section(login):
            raise xmlrpclib.Fault(201, "No password configured.")
        goodpass = config.get_default(login, "password", "").strip(" ")
        if goodpass == "":
            log.error("Invalid configuration 'password' for login '%s'." % ( login ) )
            raise xmlrpclib.Fault(201, "No password configured.")                
        if goodpass != password: 
            raise xmlrpclib.Fault(201, "Invalid login or password.")

        # Create session.
        session = kweb_session.ksession_get_session(database=sess_database)
        session.data["kpsapi"] = 1
        session.data["start_stamp"] = int(time.time())

        # Load security context.
        security_ctx = config.get_default(login, "security_ctx", "").strip(" ")
        if security_ctx not in valid_security_contexts:
            log.error("Invalid configuration 'security_ctx' for login '%s'." % ( login ) )
            raise xmlrpclib.Fault(106, "Invalid KPS API configuration.")
        session.data["security_ctx"] = security_ctx
        if session.data["security_ctx"] == KAPI_SECURITY_CTX_ORG:
            str_org_id = config.get_default(login, "org_id", "").strip(" ")
            if not str_org_id.isdigit():
                log.error("Invalid configuration 'org_id' for login '%s'." % ( login ) )
                raise xmlrpclib.Fault(106, "Invalid KPS API configuration.")
            org_id = int(str_org_id)
            if org_id == 0:
                org_id = sdb_get_main_org_id()
                if not org_id:
                     raise xmlrpclib.Fault(241, "No main organization yet.")
            session.data["org_id"] = org_id

        # Save session.
        session.save()

        log.info("User '%s' logged... session id: '%s'." % ( login, session.sid ) )
        return session.sid
        
    # Get the security context user is logged in.
    # Returns: (string) security context
    def get_security_context(self, sid):
        # Load session.
        session = session_load(sid)

        return session.data["security_ctx"]

    # Get the organization id to which the API user is bound.
    # Returns: (str bigint) organization ID
    def get_security_context_org_id(self, sid):
        # Load session.
        session = session_load(sid)

        # Make sure user is logged with the KAPI_SECURITY_CTX_ORG security context.
        session_security_context_check(session, KAPI_SECURITY_CTX_ORG)

        return bigint_to_str(session.data["org_id"])

    # Add a KPS user in the specified organization.
    # Returns: (str bigint) user ID
    def add_user(self, sid, org_id, full_name, email, login, password):
        # Load session.
        session = session_load(sid)

        # Initialize the database (kctl).
        db_init()

        # Validate parameters.
        org_id = validate_org_id(org_id)
        full_name = validate_full_name(full_name)
        email = validate_email(email)
        login = validate_login(login)
        password = validate_password(password)

        # Get/check various items in the user profile.
        org = get_org_by_org_id(org_id)
        org_id = org["org_id"]
        # FIXME - should check rights before and not after

        # Check if user has access to this organization.
        security_ctx_check_org(session, org_id)
        
        # Check for login existence.
        if sdb_login_find_by_login(login):
            raise xmlrpclib.Fault(285, "This login is already taken by another user.")

        # No email checks because it's a new user.
        # (Emails are unique to users but are not unique in the table.)
        # Clarify with the KPS maintainer... there are currently no constraints for emails.

        # Do the changes.
        first_name, last_name = full_name_split(full_name)
        prof_id = sdb_adduser(org_id, first_name, last_name)
        sdb_addlogin(org_id, prof_id, login, password)
        sdb_addpemail(prof_id, email)
        user_profile = sdb_user_profile_find_by_prof_id(prof_id)
        user_id = user_profile["user_id"]
        db_commit()
        return bigint_to_str(user_id)

    # Gets kps user id from the login		
    #def get_user_id_from_login(self, sid, login):
    #    # Load session.
    #    session = session_load(sid)
        # Initialize the database (kctl).
    #    db_init()
	
    #	user_login = get_login_row_by_login(login)
    #	user_profile = sdb_user_profile_find_by_prof_id(user_login["prof_id"])
    #    user_id = user_profile["user_id"]
    #	return bigint_to_str(user_id)
    #	pass
    
    # Modify a KPS user.
    # Returns: (integer) 1
    def modify_user(self, sid, user_id, full_name, email, login, password):
        # Load session.
        session = session_load(sid)

        # Initialize the database (kctl).
        db_init()

        # Validate parameters.
        user_id = validate_user_id(user_id)
        full_name = validate_full_name(full_name)
        email = validate_email(email)
        login = validate_login(login)
        password = validate_password(password)

        # Get/check various items in the user profile.
        user = get_user_by_user_id(user_id)
        prof_id = user["prof_id"]
        org = get_org_by_profile_id(prof_id)
        org_id = org["org_id"]
        # FIXME - should check rights before and not after

        # Check if user has access to this organization.
        security_ctx_check_org(session, org_id)

        # Get old login.
        old_login_row = sdb_login_find(prof_id)
        old_login = old_login_row["user_name"]

        # Check if new login is taken by another user.
        new_login_row = sdb_login_find_by_login(login)
        if new_login_row:
            if str(new_login_row["prof_id"]) != str(prof_id):
                # The requested login is already taken by another user.
                raise xmlrpclib.Fault(285, "This login is already taken by another user.")

        # Get old primary email.
        old_email_row = sdb_email_primary_find(user_id)
        old_email = old_email_row["email_address"]

        # Check if new email is taken by this user in secondary mode.
        # (Emails are unique to users but are not unique in the table.)
        # Clarify with the KPS maintainer... there are currently no constraints for emails.
        new_email_row = sdb_user_email_find(user_id, email)
        if new_email_row:
            if not new_email_row["is_primary"]:
                # The requested email is already used as a secondary email.
                raise xmlrpclib.Fault(295, "This email is already used as a secondary email.")

        # Do the changes.
        first_name, last_name = full_name_split(full_name)
        sdb_user_name_update(user_id, first_name, last_name)
        if login != old_login:
            sdb_login_update(old_login, login)
        sdb_password_update(login, password)
        if email != old_email:
            sdb_user_email_update(user_id, old_email, email)
        db_commit()
        return 1
        
#    def get_extra_freemium_fields(self, sid, org_id, emails):
#        import datetime
#
#        # Load session.
#        session = session_load(sid)
#        db_init()
#
#        #emails = "('mimi.toto@hotmail.com')"
#        query = "select user_name, prof_id from user_login where user_name in " + emails
#        users = db_get_all_dict(query)
#        prof_id_login_map = {}
#        prof_ids = "(-1"
#        for tmp_usr in users:
#           if tmp_usr['prof_id']:
#              prof_id_login_map[tmp_usr['prof_id']] = tmp_usr['user_name']
#              prof_ids = prof_ids + "," + str(tmp_usr['prof_id'])
#
#        prof_ids = prof_ids + ")"
#
#        query = "select prof_id, created_on, note from profiles where prof_id in " + prof_ids
#        users_extra_fields = db_get_all_dict(query)
#        result = {}
#        for extra_entry in users_extra_fields:
#           if extra_entry['prof_id'] in prof_id_login_map:
#                result[prof_id_login_map[extra_entry['prof_id']]] = {'note':str(extra_entry['note']) if extra_entry['note'] else '', 'created_on':datetime.datetime.strptime(extra_entry['created_on'], "%Y-%m-%d %H:%M:%S.%f").strftime("%Y-%m-%d") }
#
#        return result
#        pass
        

    def set_freemium_user(self, sid, org_id, email, password, license , nonce, note='', override_tbxsosd = False):
        db_init()
        #TODO: refactor the DB connection code and query exec out
        session = session_load(sid)

        #TODO: Modify kpsapi.ini and read from config file
        f_db_name = "freemium";
        #f_db_username = "freemium_user";
        #f_db_password = "123";
        f_db_host = "/var/run/postgresql";
        f_db_port = "5432";
        f_db_timeout = "5000";

	email = validate_login(email)

        esc_email = db_safestr(email)
        esc_password = db_safestr(password)
        esc_license = db_safestr(license)
        esc_nonce = db_safestr(nonce)
        esc_note = db_safestr(note)

        # Check if user has access to this organization.
        security_ctx_check_org(session, org_id)
        
        # Freemium database changes
        fdb = pgdb.connect(host = f_db_host, database = f_db_name)#,  user = f_db_username, password = f_db_password)
        fcur = fdb.cursor()
        try:
            # Delete the row with the input email address from freemium DB.
            query = "delete from freemium_users where email = %s" % (esc_email)
            fcur.execute(query)

            #insert tuple with new params into freemium DB
            query = "insert into freemium_users (org_id, email, pwd, license, nonce, note) values (%s, %s, %s, %s, %s, %s)" % (org_id, esc_email, esc_password, esc_license, esc_nonce, esc_note)
            fcur.execute(query)
            fdb.commit()
        except pgdb.DatabaseError, e:
            fdb.rollback()
            raise xmlrpclib.Fault(801, "Error updating freemium db: "+ str(e))
            #raise xmlrpclib.Fault(801, "Error while creating user")



        # Tbxsosd changes
        pemail = email
        user_id = get_user_id_from_login(email)
        if user_id:
                tmp_email = sdb_email_primary_find(user_id)
                if tmp_email and 'email_address' in tmp_email and tmp_email['email_address']:
                        pemail = tmp_email['email_address']

                if (license =='none' or license == 'confirm'):
                        self.remove_user(sid, user_id)
                        # save primary email as the login in the freemium db
                        query = "update freemium_users set email = '%s' where email = % s" % (pemail, esc_email)
                        try:
                                fcur = fdb.cursor()
                                fcur.execute(query)
                                fdb.commit()
                        except pgdb.DatabaseError, e:
                                fdb.rollback()
                                raise xmlrpclib.Fault(801, "Error updating freemium db: "+ str(e))
        else:
                if  not (license =='none' or license == 'confirm'):
                        user_id = self.add_user(sid, org_id, email, email, email, password)



        # Tbxsosd/freemium sync
        if user_id and (not (license =='none' or license == 'confirm')):
                user_login = sdb_login_find_by_login(email)
                prof_id = user_login["prof_id"]
                profile = sdb_profile_find(prof_id)

                #update created_on in freemium  
                query = "update freemium_users set created_on = %i where email = %s" % \
                        (convert_pg_timestamp_to_epoch(profile['created_on']), esc_email)
                try:
                        fcur = fdb.cursor()
                        fcur.execute(query)
                        fdb.commit()
                except pgdb.DatabaseError, e:
                        fdb.rollback()
                        raise xmlrpclib.Fault(801, "Error updating freemium db: "+ str(e))

                if override_tbxsosd:
                        sdb_password_update(email, password)
                        # update notes field
                        db_update_match("profiles", "prof_id", prof_id, "note", note)

                else:  # update freemium db with existing tbxsosd values
                       # update password
                        query  = "update freemium_users set pwd = '%s' where email = %s" % (user_login['passwd'] if (user_login['passwd'] is not None) else '', esc_email)
                        try:
                                fcur = fdb.cursor()
                                fcur.execute(query)
                                fdb.commit()
                        except pgdb.DatabaseError, e:
                                fdb.rollback()
                                raise xmlrpclib.Fault(801, "Error updating freemium db: "+ str(e))

                      #update note
                        query  = "update freemium_users set note = '%s' where email = %s" % (profile['note'] if (profile['note'] is not None) else '', esc_email)
                        try:
                                fcur = fdb.cursor()
                                fcur.execute(query)
                                fdb.commit()
                        except pgdb.DatabaseError, e:
                                fdb.rollback()
                                raise xmlrpclib.Fault(801, "Error updating freemium db: "+ str(e))

        # Kcd changes
        kcd_cfg = kbase.PropStore()

        try:
	    # Hack till kcd is able to support other license type than gold
            if (license == 'bronze' or license == 'silver'):
                license = 'gold'

            kc = FreemiumKcdClient(kcd_external_conf)
            kc.set_freemium_user(pemail, license)

        except Exception, e:
            log.error("Error connecting to kcd %s" % (str(e)))
            raise e
        
        db_commit()
        return 1

	
    # Remove KPS user.
    # Returns: (integer) 1
    def remove_user(self, sid, user_id):
        # Load session.
        session = session_load(sid)

        # Initialize the database (kctl).
        db_init()

        # Validate parameters.
        user_id = validate_user_id(user_id)

        # Get/check various items in the user profile.
        user = get_user_by_user_id(user_id)
        prof_id = user["prof_id"]
        org = get_org_by_profile_id(prof_id)
        org_id = org["org_id"]
        # FIXME - should check rights to this organization before checking if it exists (get_org_by_profile_id())

        # Check if user has access to this organization.
        security_ctx_check_org(session, org_id)

        # Do the changes.
        sdb_rmprofile(prof_id)
        sdb_login_delete(prof_id)
        db_commit()
        return 1

    # List users in an organization.
    # Returns: (array of dictionaries)
    def list_org_users(self, sid, org_id):
        # Load session.
        session = session_load(sid)

        # Initialize the database (kctl).
        db_init()

        # Validate parameters.
        org_id = validate_org_id(org_id)

        # Get/check various items in the user profile.
        org = get_org_by_org_id(org_id)
        # FIXME - should check rights to this organization before checking if it exists (get_org_by_org_id())

        # Check if user has access to this organization.
        security_ctx_check_org(session, org_id)

        # Get user profiles.
        user_profiles = sdb_get_users_profiles(org_id)
	
        o = []
        for user_profile in user_profiles:

   	    raise Exception("titotito" + str(type(user_profile)))
            prof_id = user_profile["prof_id"]
	    raise Exception("eeeeeeg")


            user_id = user_profile["user_id"]

            trow = sdb_login_find(prof_id)
            if not trow:
                raise Exception("No login set for profile ID '%s', user ID '%s'." % ( prof_id, user_id ) )
            login = trow["user_name"]
            password = trow["passwd"]
            trow = sdb_email_primary_find(user_id)
            if not trow:
                raise Exception("No primary email set for profile ID '%s', user ID '%s'." % ( prof_id, user_id ) )
            email = trow["email_address"]
            full_name = user_profile["first_name"]
            if user_profile["last_name"] != "":
                full_name += " " + user_profile["last_name"]
            o.append({"user_id" : bigint_to_str(user_id), "full_name" : full_name, 
                "login" : login, "password" : password, "email" : email})
        return o

    # Adds a secondary email to a user.
    # Returns: (integer) 1
    def add_user_email(self, sid, user_id, email):
        session = session_load(sid)
        db_init()

        # Validate parameters.
        user_id = validate_user_id(user_id)
        email = validate_email(email)

        # Get/check various items in the user profile.
        user = get_user_by_user_id(user_id)
        prof_id = user["prof_id"]
        org = get_org_by_profile_id(prof_id)
        org_id = org["org_id"]

        # FIXME - should check rights to this organization before checking if it exists (get_org_by_profile_id())
        security_ctx_check_org(session, org_id)

        # Do the changes.
        if sdb_user_email_valid(user_id, email):
            raise xmlrpclib.Fault(292, "This email already exists for that user.")
        sdb_addemail(prof_id, email)
        db_commit()
        return 1

    # Deletes a secondary email from a user.
    # Returns: (integer) 1
    def remove_user_email(self, sid, user_id, email):
        session = session_load(sid)
        db_init()

        # Validate parameters.
        user_id = validate_user_id(user_id)
        email = validate_email(email)

        # Get/check various items in the user profile.
        user = get_user_by_user_id(user_id)
        prof_id = user["prof_id"]
        org = get_org_by_profile_id(prof_id)
        org_id = org["org_id"]

        # FIXME - should check rights to this organization before checking if it exists (get_org_by_profile_id())
        security_ctx_check_org(session, org_id)

        # Check if email is primary.
        trow = sdb_email_primary_find(user_id)
        if trow["email_address"] == email:
            raise xmlrpclib.Fault(296, "Can't delete user primary email address.")

        # Do the changes.
        if not sdb_user_email_valid(user_id, email):
            raise xmlrpclib.Fault(291, "This email does not exist for that user.")
        sdb_rmemail(prof_id, email)
        db_commit()
        return 1

    # List emails associated to a user.
    # Returns: (array of dictionaries)
    def list_user_emails(self, sid, user_id):
        session = session_load(sid)
        db_init()

        # Validate parameters.
        user_id = validate_user_id(user_id)

        # Get/check various items in the user profile.
        user = get_user_by_user_id(user_id)
        prof_id = user["prof_id"]
        org = get_org_by_profile_id(prof_id)
        org_id = org["org_id"]

        # FIXME - should check rights to this organization before checking if it exists (get_org_by_profile_id())
        security_ctx_check_org(session, org_id)

        # Get list.
        email_dicts = sdb_user_emails(user_id)
        o = []
        for email_dict in email_dicts:
            o.append({"email" : email_dict["email_address"], "is_primary" : int(email_dict["is_primary"])})
        db_commit()
        return o

    # Dispatcher for all XMLRPC calls.
    def _dispatch(self, func, params):
        import syslog
        try:
            # Validate the function name and arguments.
            if func == "" or func.startswith("_") or not hasattr(self, func):
                raise xmlrpclib.Fault(103, "Invalid function.")
            handler = getattr(self, func)
            if not callable(handler):
                raise xmlrpclib.Fault(103, "Invalid function.")
            # Check arguments count. Ignore the self argument (it's a class method).
            if len(params) != (handler.im_func.func_code.co_argcount - 1):
                raise xmlrpclib.Fault(104, "Function excepts %i arguments." % ( handler.im_func.func_code.co_argcount ) )

            # Call the handler.
            return handler(*params)

        except Exception, e:
            message = "Internal error." + str(e)
            arr = traceback.format_stack() + [ traceback.format_exc() ]
            message += "\n".join(arr)
            sys.stderr.write("_dispatch exception\n " + message)
            if isinstance(e, xmlrpclib.Fault):
                # Log user errors.
                log.error("User error: %d: '%s'." % ( e.faultCode, e.faultString ) )
                raise e

            else:
                # Log exception.
                log.debug("EXCEPTION:")
                for line in traceback.format_exc().split("\n"):
                    log.debug(" --- %s" % ( line ) )

                # Raise a XMLRPC Fault.
                message = "Internal error." + e
                arr = traceback.format_stack() + [ traceback.format_exc() ]
                message += "\n".join(arr)
                raise xmlrpclib.Fault(101, message)

def main():
        # Configure logging.
        logging.config.fileConfig(ini_conf_path)

    	# Get a logger.
    	global log
    	log = logging.getLogger('tbxsos-xmlrpc')

        # Get master configuration.
        global master_config
        master_config = get_master_config()

        # Get KCD external configuration.
        global kcd_external_conf
        kcd_external_conf = get_kcd_external_conf_object(master_config=master_config)

        # Tell kctl lib to commit changes.
        kparams_set("commit", True)

        # Get an CGI XMLRPC server.
        server = CGIXMLRPCRequestHandler() #allow_none=1)
        # Get an XMLRPC server.
        #server = SimpleXMLRPCServer(("localhost", 8000))

        # Make the API public.
        #server.register_introspection_functions()

        # Register all functions from the KPSApi class.
        server.register_instance(KPSApi())

        # Handle CGI request.
        server.handle_request()
        # Start server.
        #server.serve_forever()
 
 
if __name__ == "__main__":
    main()

