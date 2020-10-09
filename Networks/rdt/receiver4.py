#!/usr/bin/env python3
# receiver.py - The receiver in the reliable data transer protocol
import packet
import socket
import sys
import udt
import argparse

RECEIVER_ADDR = ('localhost', 8080)

#Working version of GBN 10-5-2020
def receive_gbn(sock):
    initSeq = 0
    seqList = [] #Holds Sequence numbers prev received
    f = open("receiver_bio.txt", "w")
    dataStr = ''

    while True:
    #while dataStr!='END':
       #print("In true loop") #DEBUG
       pkt, senderaddr = udt.recv(sock)
       seq, data = packet.extract(pkt)
       dataStr = data.decode()

       #Does not write if duplicate pkt or FIN pkt 
       #print("data is "+data.decode()) #DEBUG
       print("receiver seq:%d, sender gave:%d" %(initSeq, seq))
       #print("data:%s" %(dataStr))
       if (seq == initSeq and not dataStr == "END"):
          #print("packet fine, writing to file")
          f.write(dataStr)
          ack = packet.make(initSeq, "ACK".encode())
          initSeq = initSeq+1
          udt.send(ack, sock, senderaddr)
       elif not seq == initSeq:
            #print("Not in ordered pkt received")
            ack = packet.make(initSeq, "ACK".encode())
       elif dataStr == 'END':
        print("Received end, we're done")
        break
    f.close() 


# Receive packets from the sender w/ SR protocol
def receive_sr(sock, windowsize):
    # Fill here
    return


# Receive packets from the sender w/ Stop-n-wait protocol
def receive_snw(sock):

    #open file for writing
    f = open("receiver_bio.txt", "w")

    # Terminal String
    endStr = ''

    # Most recent sequence number
    _seq = -1

    # Blocking Loop
    while True:

        # Block on socket data
        pkt, senderaddr = udt.recv(sock)
        seq, data = packet.extract(pkt)

        # If data is newer
        if _seq != seq:

            # Update last sequence
            _seq = seq

            # Parse data and write debugging info to logging stream
            endStr = data.decode()
            if endStr != 'END':
                f.write(endStr)

            sys.stderr.write("From: {}, Seq# {}\n".format(senderaddr, seq))
            sys.stderr.flush()

            # If string is terminal
            if endStr == 'END':
                return

            # Write socket data to output stream
            sys.stdout.write(endStr)
            sys.stdout.flush()

        # Send null ACK
        udt.send(b' ', sock, ('localhost', 9090))
    
    f.close() 



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

    if args.method == 'snw':
        receive_snw(sock)
    elif args.method == 'gbn':
        receive_gbn(sock)
    else:
        sys.stderr.write("Protocol selection must be one of [\'snw\', \'gbn\']\n")
        sys.stderr.flush()

    # Close the socket
    sock.close()