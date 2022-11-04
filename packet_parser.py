"""
packet_parser.py

Kyle West

packet_parser.py will parse a raw Wireshark packet dataset.
The program will then output analysis on some packets contained in the dataset.
"""

import sys


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
        print(line.strip())

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
