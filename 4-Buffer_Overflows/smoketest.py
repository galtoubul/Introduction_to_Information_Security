import os
import sys

import infosec.utils as utils
from infosec.utils import smoke


TEST_COMMAND = 'echo "I am g`whoami`!"; exit'
COMMAND_RESULT = 'I am groot!'


@smoke.smoke_check
def check_q1():
    with utils.in_directory('q1'):
        command = f'`python q1.py {repr(TEST_COMMAND)}`'
        result = utils.execute([sys.executable, 'q1.py', TEST_COMMAND])
        if COMMAND_RESULT not in result.stdout:
            smoke.error(f'Failed running a root command shell with {command}')
        else:
            smoke.success(f'{command} seems cool')


@smoke.smoke_check
def check_q2a():
    with utils.in_directory('q2'):
        if os.path.isfile('core'):
            os.remove('core')
        utils.execute([sys.executable, 'q2a.py'])
        if not os.path.exists('core'):
            smoke.error('Running q2a.py did not generate a `core` file')
        else:
            smoke.success('Generated a `core` file with q2a.py')


@smoke.smoke_check
def check_q2b():
    with utils.in_directory('q2'):
        command = f'`echo {repr(TEST_COMMAND)} | python q2b.py`'
        result = utils.execute([sys.executable, 'q2b.py'], TEST_COMMAND.encode())
        if COMMAND_RESULT not in result.stdout:
            smoke.error(f'Failed running a root command shell with {command}')
        else:
            smoke.success(f'{command} seems cool')


def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    check_q1()
    check_q2a()
    check_q2b()
    smoke.check_if_nonempty('q1/q1.txt')
    smoke.check_if_nonempty('q2/q2a.txt')
    smoke.check_if_nonempty('q2/q2b.txt')
    smoke.check_if_nonempty('q2/shellcode.asm')


if __name__ == '__main__':
    smoketest()
