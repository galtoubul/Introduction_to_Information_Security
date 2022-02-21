from scapy.all import *


def on_packet(packet):
    """Implement this to send a SYN ACK packet for every SYN.

    Notes:
    1. Use *ONLY* the `send` function from scapy to send the packet!
    """
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].flags == 2:
        ip = IP(dst=packet[IP].src, src=packet[IP].dst)
        src_port = packet[TCP].dport
        dst_port = packet[TCP].sport
        ack_num = packet[TCP].seq + 1
        seq_num = packet[TCP].ack
        tcp = TCP(dport=dst_port, sport=src_port, ack=ack_num, seq=seq_num, flags="SA")
        send(ip / tcp)


def main(argv):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=on_packet)


if __name__ == '__main__':
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    import sys
    sys.exit(main(sys.argv))
