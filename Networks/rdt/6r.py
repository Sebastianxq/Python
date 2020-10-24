#!/usr/bin/env python3
# receiver.py - The receiver in the reliable data transer protocol
import packet
import socket
import sys
import udt
import time
import argparse

RECEIVER_ADDR = ('localhost', 8080)

# Receive packets from the sender w/ GBN protocol
def receive_gbn(sock):

    # Terminal String
    endStr = ''

    # Most recent sequence number
    _seq = -1

    # Blocking Loop
    while True:

        # Block on socket data
        pkt, senderaddr = udt.recv(sock)
        seq, data = packet.extract(pkt)

        sys.stderr.write("Received Seq: {}\n".format(seq))
        sys.stderr.flush()

        # If data is newer by exactly 1 in-order segment
        if seq == _seq + 1:# or (seq == 0 and _seq != -1):

            # Update last sequence
            _seq = seq

            # Parse data and write debugging info to logging stream
            endStr = data.decode()
            sys.stderr.write("From: {}, Seq# {}\n".format(senderaddr, seq))
            sys.stderr.flush()

            # If string is terminal
            if endStr == 'END':
                return

            # Write socket data to output stream
            sys.stdout.write(endStr)
            sys.stdout.flush()

        # Send null ACK
        ack = packet.make(seq, b' ')
        udt.send(ack, sock, ('localhost', 9090))

    return

# SNW is the SAME protocol as GBN on the receiver side
receive_snw = receive_gbn

# Receive packets from the sender w/ SR protocol
def receive_sr(sock, windowsize):
    # Fill here
    return


def parse_args():
    parser = argparse.ArgumentParser(description='Receive UDP packets.')
    parser.add_argument('method', metavar='<protocol>', type=str,
                        help='Phrase length(s)')
    return parser.parse_args()

# Main function
if __name__ == '__main__':
    args = parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(RECEIVER_ADDR)


    # This option is arbitrary but is here for sender/receiver combo scripts to test
    if args.method == 'snw':
        receive_snw(sock)
    elif args.method == 'gbn':
        receive_gbn(sock)
    else:
        sys.stderr.write("Protocol selection must be one of [\'snw\', \'gbn\']\n")
        sys.stderr.flush()

    # Close the socket
    sock.close()