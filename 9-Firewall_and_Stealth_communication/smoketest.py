import os
import infosec.utils as utils
from infosec.utils import smoke


def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    smoke.check_if_nonempty('q1/q1a.py')
    smoke.check_if_nonempty('q1/q1a.txt')
    smoke.check_if_nonempty('q1/q1b.py')
    smoke.check_if_nonempty('q1/q1b.txt')
    smoke.check_if_nonempty('q1/q1c.txt')
    smoke.check_if_nonempty('q1/q1d.py')
    smoke.check_if_nonempty('q1/q1d.txt')
    smoke.check_if_nonempty('q2/a/bigbrother.py')
    smoke.check_if_nonempty('q2/a/q2a.txt')
    smoke.check_if_nonempty('q2/b/winston.py')
    smoke.check_if_nonempty('q2/b/julia.py')
    smoke.check_if_nonempty('q2/b/q2b.txt')
    smoke.check_if_nonempty('q2/c/bigbrother.py')
    smoke.check_if_nonempty('q2/c/q2c.txt')
    smoke.check_if_nonempty('q2/d/winston.py')
    smoke.check_if_nonempty('q2/d/julia.py')
    smoke.check_if_nonempty('q2/d/q2d.txt')


if __name__ == '__main__':
    smoketest()
