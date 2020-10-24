#!/usr/bin/env python3
import socket
import sys
import _thread
import time
import string
import packet
import udt
import random
import argparse
from timer import Timer

# SETTINGS
PACKET_SIZE = 512
RECEIVER_ADDR = ('localhost', 8080)
SENDER_ADDR = ('localhost', 9090)
SLEEP_INTERVAL = 0.5 # (In seconds)
TIMEOUT_INTERVAL = 0.2
WINDOW_SIZE = 8
RETRY_ATTEMPTS = 6

# SHARED RESOURCES
base = 0
data = True
pkt_buffer = []
mutex = _thread.allocate_lock()
timer = Timer(TIMEOUT_INTERVAL)

# RELAY CONTROL
sync = False
sending = True
receiving = True

# Generate random payload of any length
def generate_payload(length=10):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str


# Send using Stop_n_wait protocol
def send_snw(sock):

    # Access to shared resources
    global sync, data, sending, receiving

    # Track packet count
    seq = 0

    # Set data proper
    data = []

    # Open local stream
    with open(filename, "r") as f:

        print("[I] SEND - Initial Stream")

        data = f.read(PACKET_SIZE).encode()
        if data:
            print("[I] SEND - Pushing to Buffer Pkt# {}".format(seq))
            pkt = packet.make(seq, data)
            pkt_buffer.append((pkt, seq))
            seq += 1


        # Sequential File Access
        while receiving and (data or pkt_buffer):

            # Delay Mutex for sister thread
            time.sleep(SLEEP_INTERVAL)
            with mutex:

                sync = True

                print("\n[I] SEND - Acquired Lock")
                print("[I] SEND - Sending Pkt# {}".format(pkt_buffer[0][1]))
                udt.send(pkt_buffer[0][0], sock, RECEIVER_ADDR)


            data = f.read(PACKET_SIZE).encode()
            if data:
                pkt = packet.make(seq, data)
                pkt_buffer.append((pkt, seq))
                seq += 1

    # Prepare & Send END packet
    with mutex:
        for i in range (0,3):
            pkt = packet.make(seq, "END".encode())            # Prepare last packet
            pkt_buffer.append(pkt)
            udt.send(pkt, sock, RECEIVER_ADDR)                # Send EOF

    print("[I] SEND - Terminating Thread, Buffer Size: {}".format(len(pkt_buffer)))
    sending = False
    return


# Send using GBN protocol
def send_gbn(sock):
    # Access to shared resources
    global sync, data, sending, receiving

    # Track packet count
    seq = 0

    # Set data proper
    data = []

    # Open local stream
    with open(filename, "r") as f:

        print("[I] SEND - Initial Stream")

        for i in range(WINDOW_SIZE):
            data = f.read(PACKET_SIZE).encode()
            if data:
                print("[I] SEND - Pushing to Buffer Pkt# {}".format(seq))
                pkt = packet.make(seq, data)
                pkt_buffer.append((pkt, seq))
                seq += 1


        _base = 0

        # Sequential File Access
        while receiving and (data or pkt_buffer):

            # Delay Mutex for sister thread
            time.sleep(SLEEP_INTERVAL)

            with mutex:

                sync = True

                print("\n[I] SEND - Acquired Lock")
                for pkt in pkt_buffer:
                    print("[I] SEND - Sending Pkt# {}".format(pkt[1]))
                    udt.send(pkt[0], sock, RECEIVER_ADDR)


            for i in range(base - _base):
                data = f.read(PACKET_SIZE).encode()
                if data:
                    pkt = packet.make(seq, data)
                    pkt_buffer.append((pkt, seq))
                    seq += 1
            _base = base

    # Prepare & Send END packet
    with mutex:
        for i in range (0,3):
            pkt = packet.make(seq, "END".encode())            # Prepare last packet
            pkt_buffer.append(pkt)
            udt.send(pkt, sock, RECEIVER_ADDR)                # Send EOF

    print("[I] SEND - Terminating Thread, Buffer Size: {}".format(len(pkt_buffer)))
    sending = False
    return

# Receive thread for stop-n-wait
def receive_snw(sock):

     # Shared Resource Access
    global sync, base, sending, receiving

    # Spin lock to synchronize execution
    while not sync:
        continue

    retry = RETRY_ATTEMPTS + 1

    base = 0

    # Retry Loop
    while retry and (pkt_buffer or sending):

        time.sleep(SLEEP_INTERVAL)
        with mutex:

            if timer.timeout() or not timer.running():
                retry -= 1
                timer.start()

            print("\n[I] RECV - Acquired Lock")

            try:
                # Try ACK Check
                ack, recvaddr = udt.recv(sock)
                seq, ack_data = packet.extract(ack)

                # Check for base packet reception
                if seq == base:

                    print("[I] RECV - Got ACK Seq# {}".format(seq))

                    #sys.stderr.write("ACK on Seq# {}\n".format(seq))
                    #sys.stderr.flush()

                    base += 1
                    pkt_buffer.pop(0)
                    timer.stop()
                    retry = RETRY_ATTEMPTS + 1
                    continue

                print("[W] RECV - Got Wrong ACK Seq# {}, Expected {}".format(seq, base))

            except BlockingIOError:
                continue

    receiving = False

    print("[I] RECV - Terminating Thread")
    return


# Receive thread for GBN
def receive_gbn(sock):

    # Shared Resource Access
    global sync, base, sending, receiving

    # Spin lock to synchronize execution
    while not sync:
        continue

    retry = RETRY_ATTEMPTS + 1

    base = 0

    # Retry Loop
    while retry and (pkt_buffer or sending):
       
        time.sleep(SLEEP_INTERVAL)
        with mutex:

            if timer.timeout() or not timer.running():
                retry -= 1
                timer.start()

            print("\n[I] RECV - Acquired Lock")

            for i in range(WINDOW_SIZE):

                try:
                    # Try ACK Check
                    ack, recvaddr = udt.recv(sock)
                    seq, ack_data = packet.extract(ack)

                    # Check for base packet reception
                    if seq == base:

                        print("[I] RECV - Got ACK Seq# {}".format(seq))

                        #sys.stderr.write("ACK on Seq# {}\n".format(seq))
                        #sys.stderr.flush()

                        base += 1
                        pkt_buffer.pop(0)
                        timer.stop()
                        retry = RETRY_ATTEMPTS + 1
                        continue

                    print("[W] RECV - Got Wrong ACK Seq# {}, Expected {}".format(seq, base))

                except BlockingIOError:
                    continue

    receiving = False

    print("[I] RECV - Terminating Thread")
    return

def parse_args():
    parser = argparse.ArgumentParser(description='Receive UDP packets.')
    parser.add_argument('path', metavar='<input file path>', type=str,
                        help='Phrase length(s)')
    parser.add_argument('method', metavar='<protocol>', type=str,
                        help='Phrase length(s)')
    return parser.parse_args()

# Main function
if __name__ == '__main__':

    args = parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(0)
    #sock.settimeout(1)
    sock.bind(SENDER_ADDR)

    print("pre")

    base = 0

    filename = args.path

    if args.method == 'snw':
        _thread.start_new_thread(send_snw, (sock,))
        time.sleep(1)
        _thread.start_new_thread(receive_snw, (sock,))

    elif args.method == 'gbn':
        _thread.start_new_thread(send_gbn, (sock,))
        time.sleep(1)
        _thread.start_new_thread(receive_gbn, (sock,))

    while sending or receiving:
        pass
           
    else:
        sys.stderr.write("Protocol selection must be one of [\'snw\', \'gbn\']\n")
        sys.stderr.flush()

    print("post")
    sock.close()

