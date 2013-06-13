#
# Copyright (C) 2006-2012 Opersys inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# hey emacs, this is -*- python -*-
import commands, os, sys, glob, re

# Per Laurent Birtz example.
SConsignFile("/tmp/tbxsosd.sconsign.dblite")
EnsurePythonVersion(2,3)

opts = Variables('build.conf')
opts.AddVariables(
    ListVariable('build_type', 'Server build configuration', 'full',
               ['tbxsos', 'eks', 'iks', 'full', 'kos', 'keyserver']),
    BoolVariable('mudflap', 'Build with mudflap (gcc 4.x)', 0),
    BoolVariable('mpatrol', 'Build with mpatrol', 0),
    BoolVariable('debug', 'Compile with all debug options turned on', 1),
    BoolVariable('db_debug', 'Compile with database debug option', 1),
    BoolVariable('single_dir', 'Install everything in the same directory', 0),
    ('libktools_include', 'Location of include files for libktools', '#../libktools/src'),
    ('libktools_libpath', 'Location of library files for libktools', '#../libktools/build'),
    ('tagcrypt_include', 'Location of include files for tagcrypt', '#../tagcrypt'),
    ('tagcrypt_libpath', 'Location of library files for tagcrypt', '#../tagcrypt/build'),
    ("DESTDIR", 'Root of installation', '/'),
    ('PREFIX', 'Architecture-independant files prefix', '/usr'),
    ('CONFDIR', 'Configuration file path', '/etc'),
    ('BINDIR', 'Executable path', '/usr/bin'),
    ('DBDIR', 'Where to put the SQL-PY files.', '/usr/share/teambox/db'),
    ('PYTHONDIR', 'Path to Python libraries.', '/usr/share/teambox/python'))

#
# Environment setup.
#

# Setup the build environment.
env = Environment(options = opts)
opts.Save('build.conf', env)

# Generate the help text.
Help(opts.GenerateHelpText(env))

conf_options = {}

env['CPPDEFINES'] = ['__UNIX__', '_GNU_SOURCE', 'LDAP_DEPRECATED']
env['CCFLAGS']    = ['-W', '-Wall']
env['LINKFLAGS']  = ['-rdynamic']
env['LIBS']       = []
env['CPPPATH']    = [str(env['tagcrypt_include']), str(env['libktools_include'])]
env['LIBPATH']    = [str(env['tagcrypt_libpath']), str(env['libktools_libpath'])]
env['tbxsosd_LIBS'] = []

# Debug switches.
if env['db_debug']:
    env['CPPDEFINES'] += ['KD_DB_DEBUG']

if env['debug']:
    conf_options['debug'] = 1
    env['CCFLAGS'] += ['-g', '-O0', '-g3']
    env['LINKFLAGS'] += ['-g']
    env['CPPDEFINES'] += ['KD_DEBUG', 'APR_POOL_DEBUG=7']
else:
    conf_options['debug'] = 0
    env['CCFLAGS'] += ['-O2']

#
# Build configuration.
#   

def CheckGCrypt(context):
    context.Message("Checking for libgcrypt...")
    if commands.getstatusoutput('which libgcrypt-config')[0] == 0:
        env['LINKFLAGS'] += commands.getoutput('libgcrypt-config --libs').strip().split()
        context.Result('ok')
        return 1
    else:
        context.Result('failed')
        return 0

def CheckAPR(context):
    context.Message("Checking for APR 1.x...")
    which_res = commands.getstatusoutput('which apr-config')[0]
    if which_res == 0 and commands.getoutput('apr-config --version').startswith("1."):
        env['LIBS'] += commands.getoutput('apr-config --libs').strip().split()
        env['LIBS'] += ['apr-1']
        env['CPPPATH'] += commands.getoutput('apr-config --includedir').strip().split()
        context.Result('ok')
        return 1
    else:
        context.Result('failed')
        return 0

def CheckOpenSSL(context):
    context.Message("Checking for OpenSSL...")
    which_res = commands.getstatusoutput('which pkg-config')[0]
    if commands.getstatusoutput('which pkg-config')[0] == 0:
        env['tbxsosd_LIBS'] += commands.getoutput('pkg-config openssl --libs').strip().split()
        context.Result('ok')
        return 1
    else:
        context.Result('failed')
        return 0

def CheckLibPQ(context):
    context.Message("Checking for PostgreSQL's libPQ...")
    if commands.getstatusoutput('which pg_config')[0] == 0:
        env['LIBS'] += ['pq']
        env['CPPPATH'] += commands.getoutput('pg_config --includedir').strip().split()
        context.Result('ok')
        return 1
    else:
        context.Result('failed')
        return 0

if not env.GetOption('clean'):
    conf = env.Configure(custom_tests = {'CheckLibPQ': CheckLibPQ,
                                         'CheckOpenSSL': CheckOpenSSL,
                                         'CheckAPR': CheckAPR,
                                         'CheckGCrypt': CheckGCrypt})
    if not conf.CheckLib('fl', autoadd=1):
        print "GNU flex library not found."
        Exit(1)

    if not conf.CheckLib('ldap', autoadd=1):
        print "OpenLDAP library not found."
        Exit(1)
        
    if not conf.CheckLib('tagcrypt1', autoadd=1):
        print "Tagcrypt not found (wrong tagcrypt_libpath?)."
        Exit(1)
    if not conf.CheckCHeader('tagcrypt.h'):
        print "Tagcrypt headers not found (wrong tagcrypt_include path?)."
        Exit(1)
        
    if not conf.CheckLib('ktools', autoadd=1):
        print "libktools not found (wrong libktools_libdir path?)."
        Exit(1)
    if not conf.CheckHeader('ktools.h'):
        print "libktools headers not found (wrong libktools_include path?)."
        Exit(1)
        
    if not conf.CheckLib('sasl2'):
        print "Cyrus SASL not found."
        Exit(1)
    else:
        env['tbxsosd_LIBS'] += ['sasl2']
        
    if env['mudflap']:
        if not conf.CheckLib('mudflap', autoadd=1):
            print "mudflap not found."
            Exit(1)
            
    if not conf.CheckLib('adns'):
        print "ADNS not found."
        Exit(1)
    else:
        env['tbxsosd_LIBS'] += ['adns']

    # Custom tests.

    if not conf.CheckGCrypt():
        print "libgcrypt not found."
        Exit(1)
    if not conf.CheckLibPQ():
        print "PostgreSQL's libPQ not found."
        Exit(1)
    if not conf.CheckOpenSSL():
        print "OpenSSL not found."
        Exit(1)
    if not conf.CheckAPR():
        print "Apache APR not found."
        Exit(1)

if str(env['build_type']) == 'full':
    conf_options['build_conf'] = 0
if str(env['build_type']) == 'tbxsos':
    conf_options['build_conf'] = 2
if str(env['build_type']) == 'eks':
    conf_options['build_conf'] = 4
if str(env['build_type']) == 'iks':
    conf_options['build_conf'] = 5
if str(env['build_type']) == 'kos':
    conf_options['build_conf'] = 7
if str(env['build_type']) == 'keyserver':
    conf_options['build_conf'] = 8

bc = conf_options['build_conf']

# Check the paths.
if env['single_dir']:
    prefix  = Dir(os.path.join(str(env['DESTDIR']), str(env['PREFIX'])))
    confdir = Dir(prefix)
    bindir  = Dir(prefix)
    dbdir = Dir(prefix)
    pydir = Dir(prefix)
else:
    prefix  = Dir(os.path.join(str(env['DESTDIR']), str(env['PREFIX'])))
    confdir = Dir(os.path.join(str(prefix), str(env['CONFDIR'])))
    bindir  = Dir(os.path.join(str(prefix), str(env['BINDIR'])))
    dbdir = Dir(os.path.join(str(prefix), str(env['DBDIR'])))
    pydir = Dir(os.path.join(str(prefix), str(env['PYTHONDIR'])))
#
# Target linking.
#

# Support libraries.
libfilters = SConscript('libfilters/SConscript',
                        exports = 'env',
                        variant_dir = 'build/libfilters',
                        src_dir = 'libfilters',
                        duplicate = 0)
libutils = SConscript('libutils/SConscript',
                      exports = 'env',
                      variant_dir = 'build/libutils',
                      src_dir = 'libutils',
                      duplicate = 0)
libdb = SConscript('libdb/SConscript',
                   exports = 'env',
                   variant_dir = 'build/libdb',
                   src_dir = 'libdb',
                   duplicate = 0)
libcomm = SConscript('libcomm/SConscript',
                     exports = 'env',
                     variant_dir = 'build/libcomm',
                     src_dir = 'libcomm',
                     duplicate = 0)

SConscript('db/SConscript',
           exports = 'env dbdir',
           duplicate = 0)
SConscript('kctl/SConscript',
           exports = 'env conf_options prefix bindir confdir pydir',
           duplicate = 0)
SConscript('config-stock/SConscript',
           exports = 'env conf_options',
           duplicate = 0)
SConscript('init/SConscript', exports = 'env conf_options', duplicate = 0)

# Main source
SConscript('src/SConscript',
           exports = 'env conf_options prefix bindir confdir libfilters libutils libdb libcomm',
           variant_dir = 'build/src',
           src_dir = 'src',
           duplicate = 0)
        
env.Alias('install', bindir)
env.Alias('install', dbdir)
env.Alias('install', pydir)
env.Alias('install', confdir)
