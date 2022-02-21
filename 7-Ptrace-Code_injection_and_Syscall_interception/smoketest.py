import os
import subprocess
import sys
import traceback

from infosec.utils import smoke, SmoketestFailure


def check_payload(module_path, *, cls, func, args):
    name = f'{module_path}:{cls}.{func}'
    with smoke.get_from_module(module_path, cls) as server:
        try:
            get_payload = getattr(server(), func)
            payload = get_payload(*args)
        except Exception as e:
            raise SmoketestFailure(f'Exception generating payload from {name}')

    if not isinstance(payload, bytes):
        smoke.error(
            f'Invalid payload type from {name}: expected bytes, '
            f'got {type(payload)}')
        return

    smoke.success(f'payload from {name} looks cool')


@smoke.smoke_check
def check_get_solution_payload(module_path):
    check_payload(module_path, cls='SolutionServer', func='get_payload', args=(1234,))


@smoke.smoke_check
def check_get_av_pid_payload(module_path):
    check_payload(module_path, cls='EvadeAntivirusServer', func='payload_for_getting_antivirus_pid', args=())


@smoke.smoke_check
def check_builds(source, target):
    smoke.check_if_nonempty(source)

    try:
        subprocess.check_output('make %s' % target, shell=True)
    except Exception as e:
        smoke.error(f'Exception building {target} from {source}')
        return

    smoke.success(f'Successfully built {target} from {source}')


def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    check_get_av_pid_payload('evasion.py')
    check_get_solution_payload('q1.py')
    smoke.check_if_nonempty('q1.txt')
    
    check_get_solution_payload('q2.py')
    smoke.check_if_nonempty('q2.txt')
    check_builds('q2.c', 'q2.template')
    
    check_get_solution_payload('q3.py')
    smoke.check_if_nonempty('q3.txt')
    check_builds('q3.c', 'q3.template')
    
    check_get_solution_payload('q4.py')
    smoke.check_if_nonempty('q4.txt')
    check_builds('q4.c', 'q4.template')


if __name__ == '__main__':
    smoketest()
