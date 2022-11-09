"""
packet_parser.py

Kyle West

packet_parser.py will parse a raw Wireshark packet dataset.
The program will then output analysis on some packets contained in the dataset.
"""

import sys


def parse_eth2():
    return


def parse_802_3():
    return


def parse_packet(packet_hex_string):
    """
    parse the first 64 bytes of a wireshark text packet. Each hex character is .5 bytes so every 2 digits is 1 byte
    :param: packet_hex: array containing the hex digits from the wireshark text file. Each element is 2 digits of hex
    :return:
    """
    print(packet_hex_string)
    # header keeps track of current index in packet, also indicates the number of bytes parsed
    packet_hex = packet_hex_string.split('|')[2:]
    header = 0

    # parse out dest and source MAC
    dest, src = packet_hex[0:6], packet_hex[6:12]

    # decide whether packet uses Ethernet II or 802.3
    length = int(packet_hex[12] + packet_hex[13], base=16)

    header = 14
    return


# convert a time stamp into microseconds in that day
def parse_timestamp(timestamp):
    split = timestamp.split(':')
    hrs = int(split[0])
    mins = int(split[1]) + (60 * hrs)
    micro = int(split[2].replace(',', '')) + (60 * mins * 1000000)
    return micro


def parse(file_name):
    file = open(file_name, 'r')
    line = file.readline()
    while line == '+---------+---------------+----------+\n':
        # step onto timestamp line
        time_stamp = file.readline()
        time_stamp_micro = parse_timestamp(time_stamp.split(' ')[0])

        # step onto packet line
        line = file.readline()
        parse_packet(line.strip())

        # step over empty line onto +---------+---------------+----------+ line
        file.readline()
        line = file.readline()

    return


def main(file_name):
    # open wireshark dataset
    parse(file_name)
    return


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main(sys.argv[1])
