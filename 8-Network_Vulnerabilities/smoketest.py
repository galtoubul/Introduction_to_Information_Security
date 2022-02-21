import os
import traceback

import infosec.utils as utils
from infosec.utils import smoke


@smoke.smoke_check
def check_q1():
    try:
        result = utils.execute(['python3', 'q1.py', 'q1.pcapng'])
        if result.exit_code:
            smoke.error('ERROR: `python3 q1.py q1.pcapng` exitted with non-zero code {}'
                  .format(result.exit_code))

        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if not len(lines) == 1:
            smoke.error(("ERROR: `python3 q1.py q1.pcapng` should return exactly one "
                   + "line of ('user', 'password'), (as the .pcapng should have one "
                   + "login attempt), but it returned {} lines:")
                  .format(len(lines)))
            print(result.stdout)
        else:
            smoke.success("q1.py looks good")

    except Exception as e:
        smoke.error('ERROR: Failed running/analyzing `python3 q1.py q1.pcapng`')
        traceback.print_exc()


def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    smoke.check_if_nonempty('q1.py')
    smoke.check_if_nonempty('q1.txt')
    smoke.check_if_nonempty('q1.pcapng')
    check_q1()
    smoke.check_if_nonempty('q2.py')
    smoke.check_if_nonempty('q2.txt')
    smoke.check_if_nonempty('q3.py')
    smoke.check_if_nonempty('q3.txt')


if __name__ == '__main__':
    smoketest()
