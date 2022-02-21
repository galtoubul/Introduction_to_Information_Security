import socket
import json
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from base64 import b64decode


key = b'&\x99\xc5\xfca\xc9\xdb8[\x95\x0c;\x9c\xec\x96\xba'
BLOCK_SIZE_BYTES = 16

def receive_message(port: int) -> str:
    """Receive *encrypted* messages on the given TCP port.

    As Winston sends encrypted messages, re-implement this function so to
    be able to decrypt the messages.

    Notes:
    1. The encryption is based on AES.
    2. Julia and Winston already have a common shared key, just define it on your own.
    3. Mind the padding! AES works in blocks of 16 bytes.
    """
    listener = socket.socket()
    try:
        listener.bind(('', port))
        listener.listen(1)
        connection, address = listener.accept()
        try:
            r = connection.recv(1024)

            # extract IV and cipher
            iv = r[0:BLOCK_SIZE_BYTES]
            ct = r[BLOCK_SIZE_BYTES:]

            # create EAX object to decrypt using AES-128-CBC
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # unpad
            unpadder = padding.PKCS7(BLOCK_SIZE_BYTES*8).unpadder()
            data = unpadder.update(cipher.decrypt(ct))
            plaintext = data + unpadder.finalize()

            return plaintext
        finally:
            connection.close()
    finally:
        listener.close()


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
