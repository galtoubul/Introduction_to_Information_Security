import os

from infosec import utils


C_ASM_PREFIX = utils.strong_trim(r"""
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    int input, output;

    if (argc != 2) {
        printf("USAGE: %s <number>\n", argv[0]);
        return -1;
    }

    input = atoi(argv[1]);

    asm ("MOV   EBX, %0"
        :
        : "r"(input));

    asm (
""")

C_ASM_SUFFIX = utils.strong_trim(r"""
);

    asm ("MOV   %0, EAX"
        : "=r"(output));

    printf("%d\n", output);

    return 0;
}
""")


@utils.smoke.smoke_check
def check_c_asm(source_path):
    if not os.path.isfile(source_path):
        raise utils.SmoketestFailure(f'{source_path} not found')
    with open(source_path, 'r') as fp:
        code = utils.strong_trim(fp.read())
    if not code.startswith(C_ASM_PREFIX) or not code.endswith(C_ASM_SUFFIX):
        raise utils.SmoketestFailure(
            f'You changed parts of {source_path} that should not be changed!\n'
            f'You will not be graded unless you fix this - please copy the correct '
            f'file skeleton from `smoketest.py` (or by downloading the exercise again).'
        )


def compute_number(program_path, value):
    result = utils.execute([program_path, str(value)], timeout=10)
    try:
        return int(result.stdout.strip())
    except ValueError:
        raise utils.SmoketestFailure(
            f'Expected a number as output, got {result.stdout}')


@utils.smoke.smoke_check
def check_squarebonacci(source_path):
    with utils.temporary_directory() as temporary_directory_path:
        target_path = os.path.join(temporary_directory_path, 'q2')
        utils.compile_executable(sources=[source_path], output=target_path)
        values = tuple(compute_number(target_path, i) for i in range(6))
        expected = (0, 1, 1, 2, 5, 29)
        if values != expected:
            raise utils.SmoketestFailure(
                f'Squarebonacci sequence from {source_path} should begin with '
                f'{", ".join(str(v) for v in expected)}, ... '
                f'not with {", ".join(str(v) for v in values)}, ...')


@utils.smoke.smoke_check
def check_exact_sqrt(source_path):
    with utils.temporary_directory() as temporary_directory_path:
        target_path = os.path.join(temporary_directory_path, 'q1')
        utils.compile_executable(sources=[source_path], output=target_path)
        inputs = tuple(range(-1, 10))
        expected_results = (0, 0, 1, 0, 0, 2, 0, 0, 0, 0, 3)
        for number, expected in zip(inputs, expected_results):
            result = compute_number(target_path, number)
            if result != expected:
                raise utils.SmoketestFailure(
                    f'Exact square-root (from {source_path}) of {number} '
                    f'should be {expected}, but computed result was {result}')


def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    check_c_asm('q1.c')
    utils.smoke.check_if_compiles('q1.c')
    check_exact_sqrt('q1.c')

    check_c_asm('q2a.c')
    utils.smoke.check_if_compiles('q2a.c')
    check_squarebonacci('q2a.c')

    check_c_asm('q2b.c')
    utils.smoke.check_if_compiles('q2b.c')
    check_squarebonacci('q2b.c')

    utils.smoke.check_if_nonempty('q3.txt')


if __name__ == '__main__':
    smoketest()
