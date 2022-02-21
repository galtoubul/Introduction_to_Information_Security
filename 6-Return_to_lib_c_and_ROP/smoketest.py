import os
import shutil
import subprocess
import sys
import time
import traceback
import base64

import infosec.utils as utils
from infosec.utils import smoke


TEST_COMMAND = 'echo "I am g`whoami`!"; exit'
COMMAND_RESULT = 'I am groot!'


PATH_TO_SUDO = './sudo'


def check_arg_from_function(module_path, function_name, *args, **kwargs):
    try:
        with smoke.get_from_module(module_path, function_name) as func:
            result = func(*args, **kwargs)
    except Exception:
        smoke.error(f'Exception generating arg from {module_path}')
        raise

    if not isinstance(result, (bytes, bytearray)):
        smoke.error(f'Invalid arg type for {module_path}: type was {type(result)}'
                    f', expected `bytes` (or `bytearray`)')
        return False, result

    smoke.success(f'Generated arg from {module_path}')
    return True, base64.b64encode(result)


@smoke.smoke_check
def check_q1a():
    if os.path.isfile('core'):
        os.remove('core')
    success, arg = check_arg_from_function('q1a.py', 'get_crash_arg')
    if not success:
        return
    command = f'`{PATH_TO_SUDO} {repr(arg.decode("latin-1"))}` (q1a.py)'
    utils.execute([PATH_TO_SUDO, arg])
    if not os.path.exists('core'):
        smoke.error(f'Running {command} did not generate a `core` file!')
        return
    smoke.success(f'q1a.py seems cool')


@smoke.smoke_check
def check_q1b():
    success, arg = check_arg_from_function('q1b.py', 'get_arg')
    if not success:
        return
    command = f'`echo {repr(TEST_COMMAND)} | {PATH_TO_SUDO} {repr(arg.decode("latin-1"))}` (q1b.py)'
    result = utils.execute([PATH_TO_SUDO, arg], TEST_COMMAND.encode())
    if COMMAND_RESULT not in result.stdout:
        smoke.error(f'Failed running a root command shell using {command}!')
        return
    smoke.success(f'q1b.py seems cool')


@smoke.smoke_check
def check_q1c():
    success, arg = check_arg_from_function('q1c.py', 'get_arg')
    if not success:
        return
    command = f'`echo {repr(TEST_COMMAND)} | {PATH_TO_SUDO} {repr(arg.decode("latin-1"))}` (q1c.py)'
    result = utils.execute([PATH_TO_SUDO, arg], TEST_COMMAND.encode())
    if COMMAND_RESULT not in result.stdout:
        smoke.error(f'Failed running a root command shell using {command}!')
        return
    if result.exit_code != 0x42:
        smoke.error(f'The shell did not exit with a code of 0x42 (66) using {command}!')
        return
    smoke.success(f'q1c.py seems cool')


@smoke.smoke_check
def check_q3():
    success, arg = check_arg_from_function('q3.py', 'get_arg')
    if not success:
        return

    command = f'`{PATH_TO_SUDO} {repr(arg.decode("latin-1"))}` (q3.py)'

    prefix = 'auth='
    result = utils.execute([
        '/usr/bin/gdb', '--batch',
        '-ex', 'run', '-ex', 'flush(stdout)', '-ex', 'printf "{}%d\n", (int)auth'.format(prefix),
        '--args', PATH_TO_SUDO, arg])

    if prefix not in result.stdout:
        smoke.error(f'Failed debugging sudo with the argument from {command}!')
        return

    try:
        auth_line = result.stdout[result.stdout.find(prefix):].strip().splitlines()[0]
        auth = int(auth_line[len(prefix):])
    except:
        smoke.error(f'Failed debugging sudo with the argument from {command}!')
        return

    if auth == 0:
        smoke.error(f'Debugging your {command}, it seems auth is stil 0!')
        return

    smoke.success(f'q3.py seems cool')


@smoke.smoke_check
def check_q4():
    success, arg = check_arg_from_function('q4.py', 'get_arg')
    if not success:
        return

    command = f'`{PATH_TO_SUDO} {repr(arg.decode("latin-1"))}` (q4.py)'

    current_user_sudo = os.path.join(
        os.path.dirname(PATH_TO_SUDO), 'sudo_smoketest')
    try:
        # Create a copy of sudo, not owned by root, so we can kill it
        shutil.copy(PATH_TO_SUDO, current_user_sudo)
        # Create a 'head' process to pipe sudo into, and this will keep the
        # the output from growing while allowing the sudo program to write.
        head = subprocess.Popen(['/usr/bin/head', '-n', '15'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # Pipe sudo into head
        sudo = subprocess.Popen([current_user_sudo, arg], stdout=head.stdin)
        # Let this run for a second
        time.sleep(2)
        # Kill both, and then analyze the results
        sudo.kill()
        head.kill()
        lines = head.stdout.read().strip().splitlines()
        if len(lines) < 10:
            smoke.error(f'Failed getting a large amount of lines with {command}!')
        elif any(b'to your leader!' not in line for line in lines):
            smoke.error(f'Failed finding a call to your leader in the output from {command}!')
        else:
            smoke.success(f'q4.py seems cool')
    finally:
        if os.path.isfile(current_user_sudo):
            os.remove(current_user_sudo)

@smoke.smoke_check
def check_q5():
    success, arg = check_arg_from_function('q5.py', 'get_arg')
    if not success:
        return

    command = f'`{PATH_TO_SUDO} {repr(arg.decode("latin-1"))}` (q5.py)'
    result = utils.execute([PATH_TO_SUDO, arg], command.encode())

    lines = result.stdout.strip().splitlines()
    if len(lines) != 16:
        smoke.error(f'Failed getting exactly 16 lines with {command}!')
    elif any('to your leader!' not in line for line in lines):
        smoke.error(f'Failed finding calls to your leader in the output from {command}!')
    else:
        smoke.success(f'q5.py seems cool')


def get_search(*args, **kwargs):
    try:
        search = utils.import_module('search.py')
        return search.GadgetSearch(*args, **kwargs)
    except Exception:
        smoke.error('Failed loading the gadget search engine')
        raise

@smoke.smoke_check
def check_q_search():
    gs = get_search('./libc.bin', 0x123)
    pop_eax = set(gs.find_all('POP EAX'))

    if not pop_eax:
        smoke.error('search.py found no matches for "POP EAX"')
        return

    bad_types = set(type(addr) for addr in pop_eax
                    if not isinstance(addr, int))
    if bad_types:
        smoke.error(f'search.py should return addresses as `int`, but got '
                    f'{", ".join(f"`{t.__name__}`" for t in bad_types)}')
        return

    null_gs = get_search('/dev/null', 0x123)
    if any(True for _ in null_gs.find_all('POP EAX')):
        smoke.error(f'search.py finds results even for invalid memory dumps '
                    f'(such as {os.devnull})')
        print('You probably want to use `self.dump` from GadgetSearch, '
              'instead of opening "./libc.bin" on your own')
        return

    offset_gs = get_search('./libc.bin', 0x124)
    pop_eax_offset = set(addr + 1 for addr in pop_eax)
    if set(offset_gs.find_all('POP EAX')) != pop_eax_offset:
        smoke.error(f'search.py does not shift addresses by `self.start_addr`')
        print('Make sure you are adding `self.start_addr` to the offsets in '
              'the memory dump')
        return

    try:
        regs = ('esi', 'edi')
        gadget_format = 'MOV {0}, {1}'
        expected = set([
            gadget_format.format(reg1, reg2)
            for reg1 in regs
            for reg2 in regs
        ])
        cmds = set(gs.format_all_gadgets('MOV {0}, {1}', ('esi', 'edi')))
        if not set(cmds) == set(expected):
            smoke.error('Unexpected output with format_all_gadgets!')
            print(f'Expected: {expected}, Actual: {cmds}')
            return
    except Exception:
        smoke.error('Failed using the gadget search engine')
        raise

    smoke.success(f'search.py seems cool')

def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    smoke.check_if_nonempty('q1a.txt')
    smoke.check_if_nonempty('q1a.py')
    check_q1a()
    smoke.check_if_nonempty('q1b.txt')
    smoke.check_if_nonempty('q1b.py')
    check_q1b()
    smoke.check_if_nonempty('q1c.txt')
    smoke.check_if_nonempty('q1c.py')
    check_q1c()
    check_q_search()
    smoke.check_if_nonempty('q3.txt')
    smoke.check_if_nonempty('libc.bin')
    smoke.check_if_nonempty('q3.py')
    check_q3()
    smoke.check_if_nonempty('q4.txt')
    smoke.check_if_nonempty('q4.py')
    check_q4()
    smoke.check_if_nonempty('q5.txt')
    smoke.check_if_nonempty('q5.py')
    check_q5()


if __name__ == '__main__':
    smoketest()
