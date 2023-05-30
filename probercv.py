#!/usr/bin/env python3

import os
import sys
import socket

from binascii import hexlify

first = True
port = int(sys.argv[1])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', port))

with os.fdopen(sys.stdout.fileno(), 'wb', closefd=False) as stdout:
    while True:
        data, addr = sock.recvfrom(2048)
        # strip the pcap file header from all but the first packet
        if first:
            first = False
        else:
            data = data[24:]

        stdout.write(data)
        stdout.flush()
