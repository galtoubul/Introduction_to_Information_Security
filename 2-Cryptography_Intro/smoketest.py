import contextlib
import os
import numbers

from q2_atm import ATM, ServerResponse
from infosec import utils


def decrypt_with(module_path, function_name, what, encrypted_value, expected_type):
    with utils.smoke.get_from_module(module_path, function_name) as function:
        try:
            decrypted_value = function(encrypted_value)
        except Exception as e:
            raise utils.SmoketestFailure(
                f'Exception decrypting {what} using {module_path}') from e
    utils.smoke.type_check(decrypted_value, expected_type,
                           f'Invalid type for decrypted {what} using {module_path}')
    return decrypted_value


def check_extraction(module_path, function_name, what, value, encryption_func, expected_type):
    encrypted_val = encryption_func(value)
    decrypted_val = decrypt_with(
        module_path, function_name, what, encrypted_val, expected_type)
    if decrypted_val != value:
        raise utils.SmoketestFailure(
            f'Decryption of {what} doesn\'t work for {repr(value)} - result was {repr(decrypted_val)}')


@contextlib.contextmanager
def get_cipher(module_path, key):
    with utils.smoke.get_from_module(module_path, 'RepeatedKeyCipher') as cipher_class:
        yield cipher_class(key)


@contextlib.contextmanager
def get_breaker(module_path):
    with utils.smoke.get_from_module(module_path, 'BreakerAssistant') as breaker_class:
        yield breaker_class()


@utils.smoke.smoke_check
def check_q1a(module_path):
    with get_cipher(module_path, b'abc') as cipher:
        try:
            encrypted = cipher.encrypt('abcab')
        except Exception as e:
            raise utils.SmoketestFailure(
                f'Exception encrypting with {module_path}') from e

    if not isinstance(encrypted, bytes):
        raise utils.SmoketestFailure(
            f"Encryption with {module_path} doesn't return `bytes`, it returns a {type(encrypted)}")

    if encrypted != bytes([0] * 5):
        raise utils.SmoketestFailure(
            f'Encryption doesnt seem right with {module_path}')


@utils.smoke.smoke_check
def check_q1b(module_path):
    with get_cipher(module_path, b'abc') as cipher:
        try:
            decrypted = cipher.decrypt(b')+CUP')
        except Exception as e:
            raise utils.SmoketestFailure(
                f'Exception decrypting with {module_path}') from e

    if not isinstance(decrypted, str):
        raise utils.SmoketestFailure(
            f"Decryption with {module_path} doesn't return `str`, it returns a {type(decrypted)}")

    if decrypted != 'HI 42':
        raise utils.SmoketestFailure(
            f'Decryption doesnt seem right with {module_path}')


@utils.smoke.smoke_check
def check_q1c(module_path):
    def breaker_score(breaker, text):
        try:
            result = breaker.plaintext_score(text)
        except Exception as e:
            raise utils.SmoketestFailure(
                f'Error computing plaintext scores with {module_path} on {repr(text)}') from e
        if not isinstance(result, numbers.Number):
            raise utils.SmoketestFailure(
                f'Generated score by {module_path} for {repr(text)} is {repr(result)} (not a number!)')
        return result

    with get_breaker(module_path) as breaker:
        text1 = '1A\xfe~\xf6'
        text2 = 'Hello'
        if breaker_score(breaker, text1) >= breaker_score(breaker, text2):
            utils.smoke.warning(f'The score of {repr(text1)} is higher than the score of {repr(text2)}. While'
                                'not strictly an error, this is probably bad')


@utils.smoke.smoke_check
def check_q1d(module_path):
    with get_breaker(module_path) as breaker:
        try:
            result = breaker.brute_force(b'\x01\x02\x03\x04\x05', 2)
        except Exception as e:
            raise utils.SmoketestFailure(
                f'Error brute forcing cipher text with {module_path}') from e
    if not isinstance(result, str):
        raise utils.SmoketestFailure(
            f"Brute forcing with {module_path} doesn\'t return a string, it returns a {type(result)}")


@utils.smoke.smoke_check
def check_q1e(module_path):
    with get_breaker(module_path) as breaker:
        try:
            result = utils.smoke.timed_run(
                num_secs=10,
                action=lambda : breaker.smarter_break(b'a' * 32, 16),
                timeout_message=f'Smart break with {module_path} timed out (10 seconds)'
            )
        except TimeoutError:
            raise utils.SmoketestFailure(
                f'Smart break with {module_path} timed out (10 seconds)')
        except Exception as e:
            raise utils.SmoketestFailure(
                f'Error smart breaking with {module_path}') from e

    if not isinstance(result, str):
        raise utils.SmoketestFailure(
            f"Smart breaking with {module_path} doesn\'t return a string, it returns a {type(result)}")


@utils.smoke.smoke_check
def check_q2a(module_path):
    return check_extraction(
        module_path=module_path,
        function_name='extract_PIN',
        what='PIN', value=1234,
        encryption_func=ATM().encrypt_PIN,
        expected_type=int
    )


@utils.smoke.smoke_check
def check_q2b(module_path):
    return check_extraction(
        module_path=module_path,
        function_name='extract_credit_card',
        what='credit card', value=123456789,
        encryption_func=ATM().encrypt_credit_card,
        expected_type=int
    )


@utils.smoke.smoke_check
def check_q2c(module_path):
    with utils.smoke.get_from_module(module_path, 'forge_signature') as forge_signature:
        try:
            signature = forge_signature()
        except Exception as e:
            raise utils.SmoketestFailure(
                f'Exception forging a signature with {module_path}') from e

    if not isinstance(signature, ServerResponse):
        raise utils.SmoketestFailure(
            f'Signature should be a ServerResponse but is a {type(signature)}')

    try:
        if not ATM().verify_server_approval(signature):
            raise utils.SmoketestFailure(
                f'Verification does not pass with signature from {module_path}')
    except Exception as e:
        raise utils.SmoketestFailure(
            f'Exception while running the verification on response from {module_path}') from e


def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    check_q1a('q1.py')
    check_q1b('q1.py')
    check_q1c('q1.py')
    utils.smoke.check_if_nonempty('q1c.txt')
    check_q1d('q1.py')
    utils.smoke.check_if_nonempty('q1d.txt')
    check_q1e('q1.py')
    utils.smoke.check_if_nonempty('q1e.txt')
    check_q2a('q2.py')
    utils.smoke.check_if_nonempty('q2a.txt')
    check_q2b('q2.py')
    utils.smoke.check_if_nonempty('q2b.txt')
    check_q2c('q2.py')
    utils.smoke.check_if_nonempty('q2c.txt')


if __name__ == '__main__':
    smoketest()
