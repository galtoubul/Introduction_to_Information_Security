import os

import infosec.utils as utils
from infosec.utils import smoke

def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    smoke.check_if_nonempty('q1/q1.py')
    smoke.check_if_nonempty('q1/q1.txt')
    smoke.check_if_nonempty('q2/q2.py')
    smoke.check_if_nonempty('q2/q2.txt')
    smoke.check_if_nonempty('q3/q3.py')
    smoke.check_if_nonempty('q3/q3.txt')
    smoke.check_if_nonempty('q4/q4.py')
    smoke.check_if_nonempty('q4/q4.txt')
    smoke.check_if_nonempty('q5/q5.py')
    smoke.check_if_nonempty('q5/q5.txt')

if __name__ == '__main__':
    smoketest()
