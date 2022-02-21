import socket
from scapy.all import *
from itertools import zip_longest
from winston import grouper


SRC_PORT = 65000
# set for all seq numbers that Julia got
seq_set = set()
# key: packet's seq number | value: packet's reserved bits
bits_dic = {}


def on_packet(packet):
    if packet[TCP].seq not in seq_set:
        seq_set.add(packet[TCP].seq)
        bits_dic[packet[TCP].seq] = packet[TCP].reserved


# Filters packets so that only packets from SRC_PORT with TCP layer will be parsed
def packet_filter(packet) -> bool:
    if packet.haslayer(TCP) and packet[TCP].sport == SRC_PORT:
            return True
    return False


# Stop sniffing when the number of different SEQ numbers equals ACK number
def stop_con(packet) -> bool:
    return len(seq_set) == packet[TCP].ack


def parse_msg() -> str:
    # Builds a string by concatenating 3-bits representation of reserved bits
    bits_str = ''.join([format(t,'#05b')[2:] for t in [*bits_dic.values()]])
    # Builds a string by concatenating characters representation
    # of each 8-bits from bits_str
    return ''.join([chr(int(''.join(t), 2)) for t in grouper(bits_str, 8, '0')])


def receive_message(port: int) -> str:
    """Receive *hidden* messages on the given TCP port.

    As Winston sends messages encoded over the TCP metadata, re-implement this
    function so to be able to receive the messages correctly.

    Notes:
    1. Use `SRC_PORT` as part of your implementation.
    """
    sniff(lfilter=packet_filter, prn=on_packet, stop_filter=stop_con)
    return parse_msg()


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
