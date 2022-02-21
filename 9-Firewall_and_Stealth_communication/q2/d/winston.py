import socket
from scapy.all import *
import math
from itertools import zip_longest


SRC_PORT = 65000
BIT_PER_PACKET = 3


# Used: https://stackoverflow.com/questions/434287/what-is-the-most-pythonic-way-to-iterate-over-a-list-in-chunks
# Creates an iterable of tuples with n elements each
# For the last tuple: pad with fillvalue if necessary
def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def send_message(ip: str, port: int):
    """Send a *hidden* message to the given ip + port.

    Julia expects the message to be hidden in the TCP metadata, so re-implement
    this function accordingly.

    Notes:
    1. Use `SRC_PORT` as part of your implementation.
    """
    sentence = 'I love you'
    # Builds a string by concatenating 8-bits representation of sentence's charectars
    bits_str = ''.join([format(ord(c), '#010b')[2:] for c in sentence])
    # Builds a list of decimal representation of each 3-bits binary number from bits_str
    reserved_bits = [int(''.join(t), 2) for t in grouper(bits_str, 3, '0')]
        
    ip = IP(dst=ip)
    # ACK number for all packets will be the numbers of packets to send
    ack_num = len(reserved_bits)
    for seq_num in range(len(reserved_bits)):
        tcp = TCP(dport=port, sport=SRC_PORT, ack=ack_num, seq=seq_num, flags="SA", reserved=reserved_bits[seq_num])
        send(ip / tcp)


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
