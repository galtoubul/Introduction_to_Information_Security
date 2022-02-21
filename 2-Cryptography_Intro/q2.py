from q2_atm import ATM, ServerResponse
import itertools

def extract_PIN(encrypted_PIN) -> int:
    """Extracts the original PIN string from an encrypted PIN."""
    atm = ATM()
    for pin in range(10000):
        if atm.encrypt_PIN(pin) == encrypted_PIN:
            return pin

def extract_credit_card(encrypted_credit_card) -> int:
    """Extracts a credit card number string from its ciphertext."""
    return int(round(encrypted_credit_card**(1./3.)))

def forge_signature():
    """Forge a server response that passes verification."""
    # Return a ServerResponse instance.
    return ServerResponse(1, 1)

