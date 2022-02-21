import math
from scapy.all import *


LOVE = 'love'
unpersons = set()


def spy(packet):
    """Check for love packets and encrypted packets.

    For each packet containing the word 'love', or a packed which is encrypted,
    add the sender's IP to the `unpersons` set.

    Notes:
    1. Use the global LOVE as declared above.
    """
    love_bytes = LOVE.encode('utf-8')
    if packet.haslayer(Raw):
        load = packet[Raw].load
        if load.find(love_bytes) != -1:
            unpersons.add(packet[IP].src)
        else:
            decoded_raw = packet[Raw].load.decode('utf-8', 'ignore')
            if shannon_entropy(decoded_raw) > 3:
                unpersons.add(packet[IP].src)
        

def shannon_entropy(string: str) -> float:
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    distribution = [float(string.count(c)) / len(string)
                    for c in set(string)]
    return -sum(p * math.log(p) / math.log(2.0) for p in distribution)


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=spy)


if __name__ == '__main__':
    main()
