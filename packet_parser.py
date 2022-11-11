"""
packet_parser.py

Kyle West

packet_parser.py will parse a raw Wireshark packet dataset.
The program will then output analysis on some packets contained in the dataset.
"""

import sys

IPv4 = '0800'
RECENT_PROTOCOLS = {}
CONVERSATIONS = {}
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
    hardware_type = int(packet_hex[0] + packet_hex[1], base=16)
    protocol_type = packet_hex[2] + packet_hex[3]
    hardware_size = int(packet_hex[4], base=16)
    protocol_size = int(packet_hex[5], base=16)
    opcode = int(packet_hex[6] + packet_hex[7], base=16)
    src_ip = parse_ip(packet_hex[14:18])
    dst_ip = parse_ip(packet_hex[24:28])

    details = [hardware_type, protocol_type, hardware_size, protocol_size, opcode, src_mac, src_ip, dst_mac, dst_ip]

    # Check conversations!
    check_communications((src_mac, dst_mac, 'ARP'))

    return details, 'ARP'


def parse_STP(packet_hex, length, control, src_mac, dst_mac):
    """
    parse an STP packet
    """

    # parse packet
    protocol = packet_hex[0] + packet_hex[1]
    protocol_version = int(packet_hex[2], base=16)
    bpdu_type = packet_hex[3]
    flags = packet_hex[4]

    # Root identifier
    root_bridge = int(packet_hex[5] + packet_hex[6], base=16)
    # first 4 bits is root priority, last 12 bits are id extension
    root_identifier = (root_bridge & 0xF000, root_bridge & 0x0FFF, parse_mac(packet_hex[7:13]))

    path_cost = int(packet_hex[13] + packet_hex[14] + packet_hex[15] + packet_hex[16], base=16)

    # Bridge identifier
    bridge = int(packet_hex[17] + packet_hex[18], base=16)
    # first 4 bits is bridge priority, last 12 bits are id extension
    bridge_identifier = (bridge & 0xF000, bridge & 0x0FFF, parse_mac(packet_hex[19:25]))

    port_identifier = packet_hex[25] + packet_hex[26]
    msg_age = int(packet_hex[27] + packet_hex[28], base=16) / 256
    max_age = int(packet_hex[29] + packet_hex[30], base=16) / 256
    hello_time = int(packet_hex[31] + packet_hex[32], base=16) / 256
    fwrd_delay = int(packet_hex[33] + packet_hex[34], base=16) / 256

    # package up the details
    details = [protocol, protocol_version, bpdu_type, flags, root_identifier, path_cost,
               bridge_identifier, port_identifier, msg_age, max_age, hello_time, fwrd_delay]

    # Check conversations!
    check_communications((src_mac, dst_mac, 'STP'))

    return details, 'STP'


def parse_CDP(packet_hex, length, control, org_code, pid, src_mac, dst_mac):
    """
    parse a CDP packet
    """
    # There is too many bytes in the frame. TODO: look at the first 64 bytes, 22 parsed so far
    # We can check for communications though.

    # Check conversations!
    check_communications((src_mac, dst_mac, 'CDP'))

    return [], 'CDP'


def parse_802_3(packet_hex, length, src_mac, dst_mac):
    """
    parse a 802.3 frame
    """
    DSAP = packet_hex[0]
    SSAP = packet_hex[1]
    control = packet_hex[2]

    if DSAP == '42' and SSAP == '42':
        return parse_STP(packet_hex[3:], length, control, src_mac, dst_mac)
    elif DSAP == 'aa' and SSAP == 'aa':
        org_code = packet_hex[3] + ':' + packet_hex[4] + ':' + packet_hex[5]
        pid = packet_hex[6] + packet_hex[7]
        return parse_CDP(packet_hex[8:], length, control, org_code, pid, src_mac, dst_mac)

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
            return parse_ARP(packet_hex[14:], src, dst)
    else:
        return parse_802_3(packet_hex[14:], length, src, dst)


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


def check_communications(src_dst_protocol):
    global MAC_CONVERSATIONS
    # checks the CONVERSATIONS dictionary for a communication then updates
    flipped = (src_dst_protocol[1], src_dst_protocol[0], src_dst_protocol[2])
    if src_dst_protocol in CONVERSATIONS and CONVERSATIONS[src_dst_protocol] == 0:
        MAC_CONVERSATIONS += 1
        CONVERSATIONS[src_dst_protocol] = 1
    elif flipped in CONVERSATIONS and CONVERSATIONS[flipped] == 0:
        MAC_CONVERSATIONS += 1
        CONVERSATIONS[flipped] = 1
    elif src_dst_protocol not in CONVERSATIONS and flipped not in CONVERSATIONS:
        CONVERSATIONS[src_dst_protocol] = 0


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
    for protocol in RECENT_PROTOCOLS.keys():
        print(protocol + ' ' + str(RECENT_PROTOCOLS[protocol]))
    print(MAC_CONVERSATIONS)
    return


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main(sys.argv[1])
