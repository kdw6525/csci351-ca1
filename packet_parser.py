"""
packet_parser.py

Kyle West

packet_parser.py will parse a raw Wireshark packet dataset.
The program will then output analysis on some packets contained in the dataset.
"""

import sys

IPv4 = '0800'
RECENT_PROTOCOLS = {}
ARP_REQUESTS = {}
MAC_CONVERSATIONS = 0
IP_CONVERSATIONS = 0
PORT_CONVERSATIONS = 0


def parse_IPv4():
    """
    parse a IPv4 packet
    """

    return


def parse_ARP(packet_hex, src_mac, dst_mac):
    """
    parse an ARP packet
    """
    global MAC_CONVERSATIONS
    hardware_type = int(packet_hex[0] + packet_hex[1], base=16)
    protocol_type = packet_hex[2] + packet_hex[3]
    hardware_size = int(packet_hex[4], base=16)
    protocol_size = int(packet_hex[5], base=16)
    opcode = int(packet_hex[6] + packet_hex[7], base=16)
    src_ip = parse_ip(packet_hex[14:18])
    dst_ip = parse_ip(packet_hex[24:28])

    details = [hardware_type, protocol_type, hardware_size, protocol_size, opcode, src_mac, src_ip, dst_mac, dst_ip]

    # if it's a request insert it into the ARP request dictionary
    if opcode == 1:
        ARP_REQUESTS[src_ip + dst_ip] = details
    # if it's a reply check for a request
    elif opcode == 2 and ARP_REQUESTS[dst_ip + src_ip] is not None:
        ARP_REQUESTS.pop(dst_ip + src_ip)
        MAC_CONVERSATIONS += 1

    return details


def parse_802_3(length, src_mac, dst_mac, packet_hex):
    """
    parse a 802.3 frame
    """
    return


def parse_packet(packet_hex_string):
    """
    parse the first 64 bytes of a wireshark text packet. Each hex character is .5 bytes so every 2 digits is 1 byte
    :param: packet_hex: array containing the hex digits from the wireshark text file. Each element is 2 digits of hex
    :return:
    """
    print(packet_hex_string)
    packet_hex = packet_hex_string.split('|')[2:]

    # parse out dst and source MAC
    dst, src = parse_mac(packet_hex[0:6]), parse_mac(packet_hex[6:12])

    # decide whether packet uses Ethernet II or 802.3
    packet_type = packet_hex[12] + packet_hex[13]
    length = int(packet_type, base=16)

    if length > 1500:
        if packet_type == IPv4:
            return parse_IPv4()
        else:
            return parse_ARP(packet_hex[14:], src, dst), 'ARP'

    else:
        return parse_802_3(length, src, dst, packet_hex)

    return


def parse_timestamp(timestamp):
    # convert a time stamp into microseconds in that day
    split = timestamp.split(':')
    hrs = int(split[0])
    mins = int(split[1]) + (60 * hrs)
    micro = int(split[2].replace(',', '')) + (60 * mins * 1000000)
    return micro


def parse_ip(ip_hex_array):
    # ip addr = a.b.c.d
    a = str(int(ip_hex_array[0], base=16))
    b = str(int(ip_hex_array[1], base=16))
    c = str(int(ip_hex_array[2], base=16))
    d = str(int(ip_hex_array[3], base=16))
    return a + '.' + b + '.' + c + '.' + d


def parse_mac(mac_hex_array):
    # mac addr = a:b:c:d:e:f
    a = mac_hex_array[0]
    b = mac_hex_array[1]
    c = mac_hex_array[2]
    d = mac_hex_array[3]
    e = mac_hex_array[4]
    f = mac_hex_array[5]
    return a + ':' + b + ':' + c + ':' + d + ':' + e + ':' + f


def parse(file_name):
    file = open(file_name, 'r')
    line = file.readline()
    while line == '+---------+---------------+----------+\n':
        # step onto timestamp line
        time_stamp = file.readline()
        time_stamp_micro = parse_timestamp(time_stamp.split(' ')[0])

        # step onto packet line
        line = file.readline()
        current, protocol = parse_packet(line.strip())

        # Check if the current protocol has already been seen
        if protocol in RECENT_PROTOCOLS:
            # If it has been seen, we need to calc delta time
            # previous protocol has timestamp in the second to last index
            previous = RECENT_PROTOCOLS.pop(protocol)
            RECENT_PROTOCOLS[protocol] = current + [time_stamp_micro, time_stamp_micro - previous[-2]]
        else:
            # delta time is -1 as placeholder since we haven't seen this protocol before
            RECENT_PROTOCOLS[protocol] = current + [time_stamp_micro, -1]

        # step over empty line onto +---------+---------------+----------+ line
        file.readline()
        line = file.readline()

    return


def main(file_name):
    # open wireshark dataset
    parse(file_name)
    print(MAC_CONVERSATIONS)
    return


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main(sys.argv[1])
