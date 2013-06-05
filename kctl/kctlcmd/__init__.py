import types
from kreadline import Command

command_classes = []

for modnm in ['org_cmd', 'prof_cmd', 'login_cmd', 'key_cmd', 'misc_cmd']:
    current_module = __import__('kctlcmd.%s' % modnm, fromlist = [modnm])

    for nm in dir(current_module):
        obj = getattr(current_module, nm)
        if obj is Command: pass
        elif isinstance(obj, (type, types.ClassType)) and issubclass(obj, Command):
            command_classes.append(obj())
