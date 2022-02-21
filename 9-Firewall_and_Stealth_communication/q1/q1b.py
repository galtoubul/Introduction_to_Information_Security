import time
import os
from scapy.all import *


WINDOW = 60
MAX_ATTEMPTS = 15
SIZE_LIMIT = 20

# key: ip | value: list of insertion times for ip
ip_to_times_dict = {}
# blocked ips
blocked = set()


# remove all ips that their latest insertion time was before more than WINDOW seconds
def update_ips(t):
    to_remove = []
    for ip in ip_to_times_dict:
        if in_window(max(ip_to_times_dict[ip]), t) == False:
            to_remove.append(ip)
    for ip in to_remove:
        ip_to_times_dict.pop(ip)


# remove all insertion times that waren't in the last WINDOW seconds
def update_times(t, ip):
    ip_to_times_dict[ip] = [time for time in ip_to_times_dict[ip] if in_window(time, t)]


# return True only if t1 and t2 are in the same WINDOW seconds 
def in_window(t1, t2):
    return abs(t1 - t2) <= WINDOW


def on_packet(packet):
    """This function will be called for each packet.

    Use this function to analyze how many packets were sent from the sender
    during the last window, and if needed, call the 'block(ip)' function to
    block the sender.

    Notes:
    1. You must call block(ip) to do the blocking.
    2. The number of SYN packets is checked in a sliding window.
    3. Your implementation should be able to efficiently handle multiple IPs.
    """ 
    t = time.time()
    
    if not(packet.haslayer(IP) and packet.haslayer(TCP) and \
           packet[TCP].flags & 2 and packet[IP].src not in blocked):
           return

    ip = packet[IP].src

    # delete entries in our data structures if needed
    if len(ip_to_times_dict) > SIZE_LIMIT:
        update_ips(t)

    # ip was already inserted
    if ip in ip_to_times_dict:
        
        # update ip's insertion times list if needed
        update_times(t, ip)
        
        if len(ip_to_times_dict[ip]) == MAX_ATTEMPTS:
            ip_to_times_dict.pop(ip)
            block(ip)
            return
        
    if ip in ip_to_times_dict:
        ip_to_times_dict[ip].append(t)
    else:
        ip_to_times_dict[ip] = [t]


def generate_block_command(ip: str) -> str:
    """Generate a command that when executed in the shell, blocks this IP.

    The blocking will be based on `iptables` and must drop all incoming traffic
    from the specified IP."""
    return f"iptables -A INPUT -s {ip} -j DROP"


def block(ip):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    os.system(generate_block_command(ip))
    blocked.add(ip)


def is_blocked(ip):
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    return ip in blocked


def main():
    # WARNING: DO NOT MODIFY THIS FUNCTION!
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
