import socket
import json
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from base64 import b64encode
from Crypto.Random import get_random_bytes


key = b'&\x99\xc5\xfca\xc9\xdb8[\x95\x0c;\x9c\xec\x96\xba'
BLOCK_SIZE_BYTES = 16

def send_message(ip: str, port: int):
    """Send an *encrypted* message to the given ip + port.

    Julia expects the message to be encrypted, so re-implement this function accordingly.

    Notes:
    1. The encryption is based on AES.
    2. Julia and Winston already have a common shared key, just define it on your own.
    3. Mind the padding! AES works in blocks of 16 bytes.
    """
    connection = socket.socket()
    try:
        connection.connect((ip, port))
        
        # create EAX object to encrypt using AES-128-CBC
        data = b'I love you'
        iv = get_random_bytes(BLOCK_SIZE_BYTES)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # add padding
        padder = padding.PKCS7(BLOCK_SIZE_BYTES*8).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        # encrypt
        ct_bytes = cipher.encrypt(padded_data)

        # send iv + cipher
        payload = iv + ct_bytes
        connection.send(payload)
    finally:
        connection.close()


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
