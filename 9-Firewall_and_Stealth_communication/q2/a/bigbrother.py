from scapy.all import *


LOVE = 'love'
unpersons = set()


def spy(packet):
    """Check for love packets.

    For each packet containing the word 'love', add the sender's IP to the
    `unpersons` set.

    Notes:
    1. Use the global LOVE as declared above.
    """
    love_bytes = LOVE.encode('utf-8')
    if packet.haslayer(Raw):
        if packet[Raw].load.find(love_bytes) != -1:
            unpersons.add(packet[IP].src)


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=spy)


if __name__ == '__main__':
    main()
