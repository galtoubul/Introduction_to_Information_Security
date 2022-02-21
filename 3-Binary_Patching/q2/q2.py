from infosec.utils import assemble
import os


def patch_program_data(program: bytes) -> bytes:
    """
    Implement this function to return the patched program. This program should
    execute lines starting with #!, and print all other lines as-is.

    Use the `assemble` module to translate assembly to bytes. For help, in the
    command line run:

        ipython3 -c 'from infosec.utils import assemble; help(assemble)'

    :param data: The bytes of the source program.
    :return: The bytes of the patched program.
    """
    path_to_py = os.path.abspath(__file__)
    path_to_dir = os.path.dirname(path_to_py)
    path_to_patch1 = os.path.join(path_to_dir, "patch1.asm")
    path_to_patch2 = os.path.join(path_to_dir, "patch2.asm")
    
    # Create a list of opcodes in decimal from patches
    patch1 = list(assemble.assemble_file(path_to_patch1))
    patch2 = list(assemble.assemble_file(path_to_patch2))

    # Patching
    prog_bytes_list = list(program)
    prog_bytes_list[1587:1587+len(patch1)] = patch1
    prog_bytes_list[1485:1485+len(patch2)] = patch2
    return bytes(prog_bytes_list)


def patch_program(path):
    with open(path, 'rb') as reader:
        data = reader.read()
    patched = patch_program_data(data)
    with open(path + '.patched', 'wb') as writer:
        writer.write(patched)


def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <readfile-program>'.format(argv[0]))
        return -1
    path = argv[1]
    patch_program(path)
    print('done')


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
