from scapy.all import *
from typing import List, Iterable
import random as r


OPEN = 'open'
CLOSED = 'closed'
FILTERED = 'filtered'


def generate_syn_packets(ip: str, ports: List[int]) -> list:
    """
    Returns a list of TCP SYN packets, to perform a SYN scan on the given
    TCP ports.

    Notes:
    1. Do NOT add any calls of your own to send/receive packets.
    """
    tcp_syns = []
    # Default sport is 20 and well-known ports are in range 0 - 1023 are in range
    src_port = r.randint(1024, 65534)
    for port in ports:
        tcp_syns.append(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S"))
    return tcp_syns


def analyze_scan(ip: str, ports: List[int], answered: Iterable, unanswered: Iterable) -> dict:
    """Analyze the results from `sr` of SYN packets.

    This function returns a dictionary from port number (int), to
    'open' / 'closed' / 'filtered' (strings), based on the answered and unanswered
    packets returned from `sr`.

    Notes:
    1. Use the globals OPEN / CLOSED / FILTERED as declared above.
    """
    results = dict()
    # answered -> closed / open
    for ans in answered:
        flags = ans[1][TCP].flags
        port = ans[1][TCP].sport
        # Check if TCP flags contains RST (4) flag
        if flags & 4:
            results[port] = CLOSED
        # Check if TCP flags are SYN (2) - ACK (16) flags
        elif flags == 18:
            results[port] = OPEN
    # unanswered -> filtered
    for unans in unanswered:
        port = unans[0][TCP].dport
        results[port] = FILTERED
    return results

def stealth_syn_scan(ip: str, ports: List[int], timeout: int):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    packets = generate_syn_packets(ip, ports)
    answered, unanswered = sr(packets, timeout=timeout)
    return analyze_scan(ip, ports, answered, unanswered)


def main(argv):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    if not 3 <= len(argv) <= 4:
        print('USAGE: %s <ip> <ports> [timeout]' % argv[0])
        return 1
    ip = argv[1]
    ports = [int(port) for port in argv[2].split(',')]
    if len(argv) == 4:
        timeout = int(argv[3])
    else:
        timeout = 5
    results = stealth_syn_scan(ip, ports, timeout)
    for port, result in results.items():
        print('port %d is %s' % (port, result))


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
