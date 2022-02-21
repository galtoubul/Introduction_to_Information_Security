import os

from infosec.utils import smoke


@smoke.smoke_check
def check_buffer_from_function(module_path, function_name, what, ascii_selector, *args, **kwargs):
    try:
        with smoke.get_from_module(module_path, function_name) as func:
            result = func(*args, **kwargs)
        result = ascii_selector(result) if ascii_selector else result
    except Exception:
        smoke.error(f'Exception generating {what} for {module_path}')
        raise

    if not isinstance(result, (bytes, bytearray)):
        smoke.error(f'Invalid {what} type for {module_path}: type was {type(result)}'
                    f', expected `bytes` or `bytearray`')
        return

    if ascii_selector and any(c >= 0x80 for c in result):
        smoke.error(f'Your {what} from {module_path} contains non-ascii bytes\n'
                    f'{repr(result)}')
        return

    smoke.success(f'Generated {what} from {module_path}')


@smoke.smoke_check
def check_shellcode(module_path, ascii=False):
    return check_buffer_from_function(module_path,
                                      'get_shellcode' if not ascii else 'get_ascii_shellcode',
                                      'shellcode',
                                      (lambda result: result) if ascii else None)


@smoke.smoke_check
def check_payload(module_path, ascii=False):
    def ascii_part(s):
        if s[-1] == 0:
            return s[4:-5]
        else:
            return s[4:-4]
    return check_buffer_from_function(module_path, 'get_payload', 'payload',
                                      ascii_part if ascii else None)


@smoke.smoke_check
def check_encode(module_path):
    return check_buffer_from_function(module_path, 'encode', 'encoding',
                                      lambda result: result[0],
                                      data=bytes(range(128, 232)),
                                      )


@smoke.smoke_check
def check_get_decoder(module_path):
    return check_buffer_from_function(module_path, 'get_decoder_code', 'decoder',
                                      (lambda val: val),
                                      indices=[0, 1, 6, 127]
                                      )


def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    smoke.check_if_nonempty('q1.txt')
    smoke.check_if_nonempty('q1.py')
    check_payload('q1.py')
    smoke.check_if_nonempty('shellcode.asm')
    smoke.check_if_nonempty('q2.py')
    check_payload('q2.py')
    check_shellcode('q2.py')
    smoke.check_if_nonempty('q2.txt')
    smoke.check_if_nonempty('q3.txt')
    smoke.check_if_nonempty('q3.py')
    check_encode('q3.py')
    check_get_decoder('q3.py')
    check_payload('q3.py', ascii=True)
    check_shellcode('q3.py', ascii=True)


if __name__ == '__main__':
    smoketest()
