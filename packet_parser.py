"""
packet_parser.py

Kyle West

packet_parser.py will parse a raw Wireshark packet dataset.
The program will then output analysis on some packets contained in the dataset.
"""

import sys

PROTOCOL_ORDER = ('STP', 'CDP', 'ARP', 'ICMP', 'TCP', 'UDP')
IPv4 = '0800'
RECENT_PROTOCOLS = {}
MAC_CONVERSATIONS = {}
IP_CONVERSATIONS = {}
PORT_CONVERSATIONS = {}


def parse_ICMP(packet_hex, layer_2_details, layer_3_details):
    """
    parse a ICMP packet, 34 bytes parsed so far. 30 left
    """
    icmp_type = packet_hex[0]
    code = packet_hex[1]
    checksum = packet_hex[2] + packet_hex[3]
    identifier = packet_hex[4] + packet_hex[5]  # can be big endian or little endian
    sequence = packet_hex[6] + packet_hex[7]  # can be big endian or little endian
    data = packet_hex[8:]

    icmp_details = [icmp_type, code, checksum, identifier, sequence, data]

    # insert some ip communications check
    check_ip_communications((layer_3_details[-2], layer_3_details[-1], 'ICMP'))
    check_mac_communications((layer_2_details[-2], layer_2_details[-1], 'ICMP'))

    return [layer_2_details, layer_3_details, icmp_details], 'ICMP'


def parse_TCP(packet_hex, layer_2_details, layer_3_details):
    """
    parse a TCP packet, 34 bytes parsed so far. 30 left
    """
    src_port = packet_hex[0] + packet_hex[1]
    dst_port = packet_hex[2] + packet_hex[3]
    raw_seq = packet_hex[4] + packet_hex[5] + packet_hex[6] + packet_hex[7]
    raw_ack = packet_hex[8] + packet_hex[9] + packet_hex[10] + packet_hex[11]
    header_len = packet_hex[12][0]
    dec_header_len = int(header_len, base=16) * 4
    flags = packet_hex[12][1] + packet_hex[13]
    window = packet_hex[14] + packet_hex[15]
    checksum = packet_hex[16] + packet_hex[17]
    urgent = packet_hex[18] + packet_hex[19]
    options = packet_hex[20:20 + (dec_header_len - 20)] if dec_header_len > 20 else []
    data = packet_hex[20 + (dec_header_len - 20):] if dec_header_len > 20 else packet_hex[20:]

    tcp_details = [raw_seq, raw_ack, header_len, flags, window, checksum,
                   urgent, options, data, src_port, dst_port]
    # check communications!
    check_port_communications((src_port, layer_3_details[-2], dst_port, layer_3_details[-1], 'TCP'))
    check_ip_communications((layer_3_details[-2], layer_3_details[-1], 'TCP'))
    check_mac_communications((layer_2_details[-2], layer_2_details[-1], 'TCP'))

    return [layer_2_details, layer_3_details, tcp_details], 'TCP'


def parse_UDP(packet_hex, layer_2_details, layer_3_details):
    """
    parse a UDP packet, 34 bytes parsed so far. 30 left
    """
    src_port = packet_hex[0] + packet_hex[1]
    dst_port = packet_hex[2] + packet_hex[3]
    length = packet_hex[4] + packet_hex[5]
    checksum = packet_hex[6] + packet_hex[7]
    data = packet_hex[8:]

    udp_details = [length, checksum, data, src_port, dst_port]

    # check communications!
    check_port_communications((src_port, layer_3_details[-2], dst_port, layer_3_details[-1], 'UDP'))
    check_ip_communications((layer_3_details[-2], layer_3_details[-1], 'UDP'))
    check_mac_communications((layer_2_details[-2], layer_2_details[-1], 'UDP'))

    return [layer_2_details, layer_3_details, udp_details], 'UDP'


def parse_IPv4(packet_hex, layer_2_details):
    """
    parse a IPv4 packet,
    """
    version = packet_hex[0][0]
    header_len = packet_hex[0][1]
    dsp = packet_hex[1]
    total_len = packet_hex[2] + packet_hex[3]
    identification = packet_hex[4] + packet_hex[5]
    frag_flags_offset = packet_hex[6] + packet_hex[7]
    ttl = packet_hex[8]
    protocol = packet_hex[9]
    checksum = packet_hex[10] + packet_hex[11]
    src_ip = parse_ip(packet_hex[12:16])
    dst_ip = parse_ip(packet_hex[16:20])
    layer_3_details = [version, header_len, dsp, total_len, identification,
                       frag_flags_offset, ttl, protocol, checksum, src_ip, dst_ip]
    # check protocol
    if protocol == '01':
        # parse ICMP
        return parse_ICMP(packet_hex[20:], layer_2_details, layer_3_details)
    elif protocol == '06':
        # parse TCP
        return parse_TCP(packet_hex[20:], layer_2_details, layer_3_details)
    elif protocol == '11':
        # parse UDP
        return parse_UDP(packet_hex[20:], layer_2_details, layer_3_details)

    return [layer_2_details, layer_3_details], 'IPv4'


def parse_ARP(packet_hex, layer_2_details):
    """
    parse an ARP packet
    """
    src_mac = layer_2_details[1]
    dst_mac = layer_2_details[2]
    hardware_type = int(packet_hex[0] + packet_hex[1], base=16)
    protocol_type = packet_hex[2] + packet_hex[3]
    hardware_size = int(packet_hex[4], base=16)
    protocol_size = int(packet_hex[5], base=16)
    opcode = int(packet_hex[6] + packet_hex[7], base=16)
    src_ip = parse_ip(packet_hex[14:18])
    dst_ip = parse_ip(packet_hex[24:28])

    layer_3_details = [hardware_type, protocol_type, hardware_size,  # arp data
                       protocol_size, opcode, src_ip, dst_ip]

    # Check conversations!
    check_mac_communications((src_mac, dst_mac, 'ARP'))

    return [layer_2_details, layer_3_details], 'ARP'


def parse_STP(packet_hex, layer_2_details, llc_details):
    """
    parse an STP packet
    """
    src_mac = layer_2_details[1]
    dst_mac = layer_2_details[2]
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

    msg_age = int(packet_hex[27] + packet_hex[28], base=16) >> 8
    max_age = int(packet_hex[29] + packet_hex[30], base=16) >> 8
    hello_time = int(packet_hex[31] + packet_hex[32], base=16) >> 8
    fwrd_delay = int(packet_hex[33] + packet_hex[34], base=16) >> 8

    # package up the details
    details = [protocol, protocol_version, bpdu_type, flags, root_identifier, path_cost,
               bridge_identifier, port_identifier, msg_age, max_age, hello_time, fwrd_delay]

    # Check conversations!
    check_mac_communications((src_mac, dst_mac, 'STP'))

    return [layer_2_details, llc_details, details], 'STP'


def parse_CDP(packet_hex, layer_2_details, llc_details):
    """
    parse a CDP packet
    """
    # There is too many bytes in the frame.
    src_mac = layer_2_details[1]
    dst_mac = layer_2_details[2]
    version = int(packet_hex[0], base=16)
    ttl = int(packet_hex[1], base=16)
    checksum = packet_hex[2] + packet_hex[3]
    # device = (type, length, device id)
    device = (packet_hex[4] + packet_hex[5], int(packet_hex[6] + packet_hex[7], base=16), packet_hex[8:14])
    sw_version = packet_hex[14] + packet_hex[15]
    sw_version_length = int(packet_hex[16] + packet_hex[17], base=16)
    data_left = packet_hex[18:]
    details = [version, ttl, checksum, device, sw_version, sw_version_length, data_left]  # CDP data

    # Check conversations!
    check_mac_communications((src_mac, dst_mac, 'CDP'))

    return [layer_2_details, llc_details, details], 'CDP'


def parse_802_3(packet_hex, layer_2_details):
    """
    parse a 802.3 frame
    """
    DSAP = packet_hex[0]
    SSAP = packet_hex[1]
    control = packet_hex[2]

    if DSAP == '42' and SSAP == '42':
        llc_details = [DSAP, SSAP, control]
        return parse_STP(packet_hex[3:], layer_2_details, llc_details)
    elif DSAP == 'aa' and SSAP == 'aa':
        org_code = packet_hex[3] + ':' + packet_hex[4] + ':' + packet_hex[5]
        pid = packet_hex[6] + packet_hex[7]
        llc_details = [DSAP, SSAP, control, org_code, pid]
        return parse_CDP(packet_hex[8:], layer_2_details, llc_details)

    return


def parse_packet(packet_hex_string):
    """
    parse the first 64 bytes of a wireshark text packet. Each hex character is .5 bytes so every 2 digits is 1 byte
    :param: packet_hex: array containing the hex digits from the wireshark text file. Each element is 2 digits of hex
    :return:
    """
    packet_hex = packet_hex_string.split('|')[2:]
    size = len(packet_hex)

    # parse out dst and source MAC
    dst, src = parse_mac(packet_hex[0:6]), parse_mac(packet_hex[6:12])

    # decide whether packet uses Ethernet II or 802.3
    packet_type = packet_hex[12] + packet_hex[13]
    length = int(packet_type, base=16)

    if length > 1500:
        layer_2_details = [packet_type, src, dst]
        if packet_type == IPv4:
            return size, parse_IPv4(packet_hex[14:], layer_2_details)
        else:
            return size, parse_ARP(packet_hex[14:], layer_2_details)
    else:
        layer_2_details = [length, src, dst]
        return size, parse_802_3(packet_hex[14:], layer_2_details)


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


def data_to_string(data_hex):
    # converts remaining data into a hex string with '|' as a byte separator
    hex_string = '|'
    for data in data_hex:
        hex_string += data + '|'
    return hex_string


def check_mac_communications(src_dst_protocol):
    global MAC_CONVERSATIONS
    # checks the CONVERSATIONS dictionary for a communication then updates
    flipped = (src_dst_protocol[1], src_dst_protocol[0], src_dst_protocol[2])
    if src_dst_protocol in MAC_CONVERSATIONS and MAC_CONVERSATIONS[src_dst_protocol] == 0:
        MAC_CONVERSATIONS[src_dst_protocol] = 1
    elif flipped in MAC_CONVERSATIONS and MAC_CONVERSATIONS[flipped] == 0:
        MAC_CONVERSATIONS[flipped] = 1
    elif src_dst_protocol not in MAC_CONVERSATIONS and flipped not in MAC_CONVERSATIONS:
        MAC_CONVERSATIONS[src_dst_protocol] = 0


def check_ip_communications(src_dst_protocol):
    global IP_CONVERSATIONS
    # checks the CONVERSATIONS dictionary for a communication then updates
    flipped = (src_dst_protocol[1], src_dst_protocol[0], src_dst_protocol[2])
    if src_dst_protocol in IP_CONVERSATIONS and IP_CONVERSATIONS[src_dst_protocol] == 0:
        IP_CONVERSATIONS[src_dst_protocol] = 1
    elif flipped in IP_CONVERSATIONS and IP_CONVERSATIONS[flipped] == 0:
        IP_CONVERSATIONS[flipped] = 1
    elif src_dst_protocol not in IP_CONVERSATIONS and flipped not in IP_CONVERSATIONS:
        IP_CONVERSATIONS[src_dst_protocol] = 0


def check_port_communications(src_dst_protocol):
    global PORT_CONVERSATIONS
    # checks the CONVERSATIONS dictionary for a communication then updates
    # src_dst_protocol is (src ip, src port, dst ip, dst port, protocol)
    flipped = (src_dst_protocol[2], src_dst_protocol[3], src_dst_protocol[0], src_dst_protocol[1], src_dst_protocol[4])
    if src_dst_protocol in PORT_CONVERSATIONS and PORT_CONVERSATIONS[src_dst_protocol] == 0:
        PORT_CONVERSATIONS[src_dst_protocol] = 1
    elif flipped in PORT_CONVERSATIONS and PORT_CONVERSATIONS[flipped] == 0:
        PORT_CONVERSATIONS[flipped] = 1
    elif src_dst_protocol not in PORT_CONVERSATIONS and flipped not in PORT_CONVERSATIONS:
        PORT_CONVERSATIONS[src_dst_protocol] = 0


def parse(file_name):
    total_packets = 0
    max_packet_size = 0
    min_packet_size = sys.maxsize
    sum_packet_size = 0
    file = open(file_name, 'r')
    line = file.readline()
    while line == '+---------+---------------+----------+\n':
        # step onto timestamp line
        time_stamp = file.readline()
        time_stamp_micro = parse_timestamp(time_stamp.split(' ')[0])

        # step onto packet line
        line = file.readline()
        size, packet = parse_packet(line.strip())
        current, protocol = packet[0], packet[1]

        # packet size statistics, size - 1 due to length of array
        max_packet_size = max(max_packet_size, size - 1)
        min_packet_size = min(min_packet_size, size - 1)
        sum_packet_size += size - 1

        # Check if the current protocol has already been seen
        if protocol in RECENT_PROTOCOLS:
            # If it has been seen, we need to calc delta time
            # previous protocol has timestamp in the second to last index
            previous = RECENT_PROTOCOLS.pop(protocol)
            RECENT_PROTOCOLS[protocol] = current + [time_stamp_micro, time_stamp_micro - previous[-3], previous[-1] + 1]
        else:
            # delta time is -1 as placeholder since we haven't seen this protocol before
            RECENT_PROTOCOLS[protocol] = current + [time_stamp_micro, -1, 1]

        total_packets += 1
        # step over empty line onto +---------+---------------+----------+ line
        file.readline()
        line = file.readline()

    # return total packets, max packet size, min packet size, average packet size
    return total_packets, max_packet_size, min_packet_size, sum_packet_size / total_packets


def print_conversations(conversations):
    # prints dictionary conversation
    print(f"{'Source':20}{'Destination':20}{'Protocol':10}{'Responded'}")
    for conversation in conversations.keys():
        responded = conversations[conversation]
        if responded == 0:
            print(f"{conversation[0]:20}{conversation[1]:20}{conversation[2]:10}{'no'}")
        else:
            print(f"{conversation[0]:20}{conversation[1]:20}{conversation[2]:10}{'yes'}")
    print()


def print_port_conversations(conversations):
    # prints dictionary conversation for ports
    print(f"{'Source':26}{'Destination':26}{'Protocol':10}{'Responded'}")
    for conversation in conversations.keys():
        responded = conversations[conversation]
        src_port = int(conversation[0], base=16)
        dst_port = int(conversation[2], base=16)
        if responded == 0:
            print(f"{conversation[1] + ':' + str(src_port):26}"
                  f"{conversation[3] + ':' + str(dst_port):26}"
                  f"{conversation[4]:10}{'no'}")
        else:
            print(f"{conversation[1] + ':' + str(src_port):26}"
                  f"{conversation[3] + ':' + str(dst_port):26}"
                  f"{conversation[4]:10}{'yes'}")
    print()


def print_distribution(conversations, total):
    # iterate through conversations and print the protocol distribution
    print(f'Protocol Distribution: \n{"Protocol":10}{"%"}')
    for protocol in PROTOCOL_ORDER:
        current = conversations[protocol]
        percent = round((current[-1] / total) * 100, 2)
        print(f'{protocol:10}{percent:>.2f}%')
    print()


def print_timestamp(details):
    timestamp = details[-3]
    delta_time = details[-2]
    print('Timestamp in milliseconds: ' + str(timestamp))
    if delta_time == -1:
        print('There are no other occurrences of this packet')
    else:
        print('Delta time in milliseconds: ' + str(delta_time))
    print()


def print_ARP(arp_details):
    """
    Prints the contents of an Ethernet II and ARP packet,
    prints the field, hex, decimal (if needed), then the meaning of the field
    """
    eth2 = arp_details[0]
    arp = arp_details[1]

    print('ARP and Ethernet II:')

    print_timestamp(arp_details)

    print('Ethernet II:')
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Type':20}{'0x' + eth2[0]:20}{int(eth2[0], base=16):<12}{'This means this is an ARP packet.'}")
    print(f"{'Destination MAC':20}{eth2[2]:20}{'':12}{'This is the MAC address of the receiver.'}")
    print(f"{'Source MAC':20}{eth2[1]:20}{'':12}{'This is the MAC address of the sender.'}")
    print()

    print('ARP:')
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Hardware type':20}{format(arp[0], '#06x'):20}{arp[0]:<12}"
          f"{'This is the hardware type: 1 means ethernet, 6 means IEEE 802 network, etc.'}")
    print(f"{'Protocol Type':20}{'0x' + arp[1]:20}{int(arp[1], base=16):<12}"
          f"{'Specifies the type of address we are trying to find.'}")
    print(f"{'Hardware Size':20}{format(arp[2], '#04x'):20}{arp[2]:<12}"
          f"{'Specifies how long the hardware addresses are.'}")
    print(f"{'Hardware Size':20}{format(arp[3], '#04x'):20}{arp[3]:<12}"
          f"{'Specifies how long the address we are trying to find is.'}")
    print(f"{'Hardware Size':20}{format(arp[4], '#06x'):20}{arp[4]:<12}"
          f"{'Specifies the type of ARP message: 1 is a request, 2 is a reply, ect.'}")
    print(f"{'Source MAC':20}{eth2[1]:20}{'':<12}"
          f"{'This is the MAC address of the sender.'}")
    print(f"{'Source IP':20}{arp[5]:20}{'':12}"
          f"{'This is the IP address of the sender.'}")
    print(f"{'Destination MAC':20}{eth2[2]:20}{'':<12}"
          f"{'This is the MAC address of the receiver.'}")
    print(f"{'Destination IP':20}{arp[6]:20}{'':12}"
          f"{'This is the IP address of the destination.'}")
    return


def print_STP(stp_details):
    """
    Prints the contents of an 802.3, 802.2, and STP packet,
    prints the field, hex, decimal (if needed), then the meaning of the field
    """
    ieee_8023 = stp_details[0]
    ieee_8022 = stp_details[1]
    stp = stp_details[2]

    print('STP, 802.3, and 802.2:')
    print_timestamp(stp_details)

    print('IEEE 802.3 Ethernet:')
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Length':20}{format(ieee_8023[0], '#06x'):20}{ieee_8023[0]:<12}{'This means the frame is 802.3'}")
    print(f"{'Destination MAC':20}{ieee_8023[2]:20}{'':12}{'This is the MAC address of the receiver.'}")
    print(f"{'Source MAC':20}{ieee_8023[1]:20}{'':12}{'This is the MAC address of the sender.'}")
    print()

    print('IEEE 802.2 Logical Link Control:')
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'DSAP':20}{'0x' + ieee_8022[0]:20}{int(ieee_8022[0], base=16):<12}"
          f"{'Destination Service Access Point represents the logical address of the destination'}")
    print(f"{'SSAP':20}{'0x' + ieee_8022[1]:20}{int(ieee_8022[1], base=16):<12}"
          f"{'Destination Service Access Point represents the logical address of the source'}")
    print(f"{'Control field':20}{'0x' + ieee_8022[2]:20}{int(ieee_8022[2], base=16):<12}"
          f"{'A U-format control field, signifies a connectionless application'}")
    print()

    print('STP:')
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Protocol Identifier':20}{'0x' + stp[0]:20}{int(stp[0], base=16):<12}"
          f"{'0x0000 Signifies that we are performing STP'}")
    print(f"{'Protocol Version ID':20}{format(stp[1], '#04x'):20}{stp[1]:<12}"
          f"{'Specifies the version of STP'}")
    print(f"{'BPDU Type':20}{'0x' + stp[2]:20}{int(stp[2], base=16):<12}"
          f"{'Bridge Protocol Data Unit Type, specifies the type message being transmitted.'}")
    print(f"{'Flags':20}{'0x' + stp[3]:20}{int(stp[3], base=16):<12}"
          f"{'Lowest order bit is the TC flag, and the highest order is the TCA flag.'}")
    print(f"{'Root Path Cost':20}{format(stp[5], '#010x'):20}{stp[5]:<12}"
          f"{'Cost of the path to the root bridge'}")
    print(f"{'Port Identifier':20}{'0x' + stp[7]:20}{int(stp[7], base=16):<12}"
          f"{'Designated port ID created by the priority and global port number.'}")
    print(f"{'Message Age':20}{format(stp[8] << 8, '#06x'):20}{stp[8] << 8:<12}"
          f"{f'Age of the configuration BPDU while this propagates the network. {stp[8]} is age in seconds.'}")
    print(f"{'Max Age':20}{format(stp[9] << 8, '#06x'):20}{stp[9] << 8:<12}"
          f"{f'Maximum age of the configuration BPDU stored on the switch. {stp[9]} is max age in seconds.'}")
    print(f"{'Hello Time':20}{format(stp[10] << 8, '#06x'):20}{stp[10] << 8:<12}"
          f"{f'Configuration BPDU transmission interval. {stp[10]} is hello time in seconds.'}")
    print(f"{'Forward Delay':20}{format(stp[11] << 8, '#06x'):20}{stp[11] << 8:<12}"
          f"{f'Delay for STP bridges to forward. {stp[11]} is forward delay in seconds.'}")
    print()

    root = stp[4]
    bridge = stp[6]
    print('STP Bridges:')
    print(f"{'Type':20}{'Priority':12}{'Extension':12}{'Address':20}{'Meaning'}")
    print(f"{'Root':20}{root[0]:<12}{root[1]:<12}{root[2]:20}"
          f"{f'The root bridge for this STP has a priority of {root[0]} and extension of {root[1]}'}")
    print(f"{'Bridge':20}{bridge[0]:<12}{bridge[1]:<12}{bridge[2]:20}"
          f"{f'This bridge for this STP has a priority of {bridge[0]} and extension of {bridge[1]}'}")

    return


def print_CDP(cdp_details):
    """
    Prints the contents of an CDP packet,
    prints the field, hex, decimal (if needed), then the meaning of the field
    """

    cdp = cdp_details[2]
    device = cdp[3]
    print('CDP:')

    print_timestamp(cdp_details)

    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Version':20}{format(cdp[0], '#04x'):20}{cdp[0]:<12}"
          f"{'Specifies the version of CDP.'}")
    print(f"{'Time to Live':20}{format(cdp[1], '#04x'):20}{cdp[1]:<12}"
          f"{'The amount of time, in seconds, that a receiver should retain the information from this packet.'}")
    print(f"{'Checksum':20}{'0x' + cdp[2]:20}{int(cdp[2], base=16):<12}"
          f"{'Standard IP checksum for error checking.'}")
    print(f"{'Type':20}{'0x' + cdp[4]:20}{int(cdp[4], base=16):<12}"
          f"{'Describes the type of CDP being performed.'}")
    print(f"{'Length':20}{format(cdp[5], '#04x'):20}{cdp[5]:<12}"
          f"{'The total length in bytes of the type, length and value fields.'}")
    print()

    print('CDP Device:')
    print(f"{'Type':12}{'Length':12}{'Address':20}{'Meaning'}")
    print(f"{device[0]:12}{device[1]:<12}{parse_mac(device[2]):20}"
          f"{'This is the device performing CDP and has these features.'}")
    print()

    print('Next fields over run the 64 byte limit on project: \n' + data_to_string(cdp[6]))

    return


def print_ICMP(icmp_details):
    """
    Prints the contents of an IPv4 and ICMP packet,
    prints the field, hex, decimal (if needed), then the meaning of the field
    """
    ipv4 = icmp_details[1]
    icmp = icmp_details[2]

    print('IPv4 and ICMP:')

    print_timestamp(icmp_details)

    print('IPv4:')
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Version':20}{'0x' + ipv4[0]:20}{int(ipv4[0], base=16):<12}{'This means we are using IPv4'}")
    print(f"{'Header Length':20}{'0x' + ipv4[1]:20}{int(ipv4[1], base=16):<12}{'Length of the header'}")
    print(f"{'DSF':20}{'0x' + ipv4[2]:20}{int(ipv4[2], base=16):<12}{'Specifies differentiated services.'}")
    print(f"{'Total Length':20}{'0x' + ipv4[3]:20}{int(ipv4[3], base=16):<12}{'Size of the entire packet.'}")
    print(f"{'Identification':20}{'0x' + ipv4[4]:20}{int(ipv4[4], base=16):<12}"
          f"{'Identifies fragmented packets.'}")
    print(f"{'Flags':20}{'0x' + ipv4[5]:20}{int(ipv4[5], base=16):<12}"
          f"{'Fragmentation flags, specifying either to not fragment or if more fragments are coming.'}")
    print(f"{'Time to Live':20}{'0x' + ipv4[6]:20}{int(ipv4[6], base=16):<12}"
          f"{'Specifies the number of hops until the packet is killed.'}")
    print(f"{'Protocol':20}{'0x' + ipv4[7]:20}{int(ipv4[7], base=16):<12}"
          f"{'Specifies the protocol, in this case it specifies ICMP'}")
    print(f"{'Checksum':20}{'0x' + ipv4[8]:20}{int(ipv4[6], base=16):<12}"
          f"{'A checksum used for error checking the header.'}")
    print(f"{'Source Address':20}{ipv4[9]:20}{'':<12}"
          f"{'The IP address of the sender.'}")
    print(f"{'Destination Address':20}{ipv4[10]:20}{'':<12}"
          f"{'The IP address of the destination.'}")
    print()

    print('ICMP:')
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Type':20}{'0x' + icmp[0]:20}{int(icmp[0], base=16):<12}"
          f"{'Specifies the type of ICMP message.'}")
    print(f"{'Code':20}{'0x' + icmp[1]:20}{int(icmp[1], base=16):<12}"
          f"{'Code to specify what the ICMP message is trying to accomplish or inform.'}")
    print(f"{'Checksum':20}{'0x' + icmp[2]:20}{int(icmp[2], base=16):<12}"
          f"{'A checksum used for error checking.'}")
    print(f"{'Identifier':20}{'0x' + icmp[3]:20}{int(icmp[3], base=16):<12}"
          f"{'Helps identify a ICMP echo and reply.'}")
    print(f"{'Sequence Number':20}{'0x' + icmp[4]:20}{int(icmp[4], base=16):<12}"
          f"{'Also used to help identify match an echo and reply.'}")
    print('Data: ' + data_to_string(icmp[5]))

    return


def print_TCP(tcp_details):
    """
    Prints the contents of an TCP packet,
    prints the field, hex, decimal (if needed), then the meaning of the field
    """

    tcp = tcp_details[2]
    print('TCP:')
    print_timestamp(tcp_details)
    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Source Port':20}{'0x' + tcp[-2]:20}{int(tcp[-2], base=16):<12}"
          f"{'Port that the sender used to send the packet.'}")
    print(f"{'Destination Port':20}{'0x' + tcp[-1]:20}{int(tcp[-1], base=16):<12}"
          f"{'Port that will receive the packet.'}")
    print(f"{'Sequence Number':20}{'0x' + tcp[0]:20}{int(tcp[0], base=16):<12}"
          f"{'Signifies the part of the data we are currently at, helps determine the corresponding ACK'}")
    print(f"{'ACK Number':20}{'0x' + tcp[1]:20}{int(tcp[1], base=16):<12}"
          f"{'If ACK flag is set, then this field is the next sequence number the sender of the ACK is expecting'}")
    print(f"{'Header Length':20}{'0x' + tcp[2]:20}{int(tcp[2], base=16):<12}"
          f"{'Specifies the number of 32-bit words the header will be, the minimum is 5 words.'}")
    print(f"{'Flags':20}{'0x' + tcp[3]:20}{int(tcp[3], base=16):<12}"
          f"{'These flags are used to specify ACK, SYN, etc.'}")
    print(f"{'Window Size':20}{'0x' + tcp[4]:20}{int(tcp[4], base=16):<12}"
          f"{'Specifies the window size, aka the amount of data that can be sent.'}")
    print(f"{'Checksum':20}{'0x' + tcp[5]:20}{int(tcp[5], base=16):<12}"
          f"{'Standard error checking for the TCP header.'}")
    print(f"{'Urgent Pointer':20}{'0x' + tcp[6]:20}{int(tcp[6], base=16):<12}"
          f"{'If the URG flag is set then this field is an offset from the sequence number.'}")
    print()
    print('Due to the options field sometimes exceeding the 64 bytes of the project here is the hex:')
    print(data_to_string(tcp[7]))
    print()
    print('Data: ' + data_to_string(tcp[8]))

    return


def print_UDP(udp_details):
    """
    Prints the contents of a UDP packet,
    prints the field, hex, decimal (if needed), then the meaning of the field
    """

    udp = udp_details[2]
    print('UDP:')
    print_timestamp(udp_details)

    print(f"{'Field':20}{'Hex/Address':20}{'Decimal':12}{'Meaning'}")
    print(f"{'Source Port':20}{'0x' + udp[-2]:20}{int(udp[-2], base=16):<12}"
          f"{'Port that the sender used to send the packet.'}")
    print(f"{'Destination Port':20}{'0x' + udp[-1]:20}{int(udp[-1], base=16):<12}"
          f"{'Port that will receive the packet.'}")
    print(f"{'Length':20}{'0x' + udp[0]:20}{int(udp[0], base=16):<12}"
          f"{'Specifies the length of the UDP header and data in bytes.'}")
    print(f"{'Checksum':20}{'0x' + udp[1]:20}{int(udp[1], base=16):<12}"
          f"{'Standard checksum for UDP.'}")

    print('Data: ' + data_to_string(udp[2]))
    return


def main(file_name):
    # parse wireshark dataset
    total_packets, max_size, min_size, avg_size = parse(file_name)
    print('Total packets: ' + str(total_packets))
    print('Max packet size: ' + str(max_size))
    print('Min packet size: ' + str(min_size))
    print('Avg packet size: ' + str(round(avg_size, 2)))
    print_distribution(RECENT_PROTOCOLS, total_packets)
    print('MAC conversations:')
    print_conversations(MAC_CONVERSATIONS)
    print('IP conversations:')
    print_conversations(IP_CONVERSATIONS)
    print('PORT conversations:')
    print_port_conversations(PORT_CONVERSATIONS)

    for protocol in PROTOCOL_ORDER:
        if protocol == 'STP':
            print_STP(RECENT_PROTOCOLS[protocol])
            print()
        elif protocol == 'CDP':
            print_CDP(RECENT_PROTOCOLS[protocol])
            print()
        elif protocol == 'ARP':
            print_ARP(RECENT_PROTOCOLS[protocol])
            print()
        elif protocol == 'ICMP':
            print_ICMP(RECENT_PROTOCOLS[protocol])
            print()
        elif protocol == 'TCP':
            print_TCP(RECENT_PROTOCOLS[protocol])
            print()
        elif protocol == 'UDP':
            print_UDP(RECENT_PROTOCOLS[protocol])
            print()
    return


if __name__ == '__main__':
    main(sys.argv[1])
