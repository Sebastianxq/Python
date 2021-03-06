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
SLEEP_INTERVAL = 1.0 # (In seconds)
TIMEOUT_INTERVAL = 1.0
WINDOW_SIZE = 4
RETRY_ATTEMPTS = 24

# SHARED RESOURCES
base = 0
data = True
pkt_buffer = []
mutex = _thread.allocate_lock()
timer = Timer(TIMEOUT_INTERVAL)

# RELAY CONTROL
sync = False
alive = True

# Generate random payload of any length
def generate_payload(length=10):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str


# Send using Stop_n_wait protocol
def send_snw(sock):

    # Access to shared resources
    global sync, data, alive

    # Track packet count
    seq = 0

    # Open local stream
    with open(filename, "r") as f:

        # Sequential File Access
        while data:

            # Lock Context
            with mutex:

                # Debugging Info
                print("[I] SEND - Acquired Lock")

                # Generate Packet & Link Buffer
                data = f.read(PACKET_SIZE).encode()
                pkt = packet.make(seq, data)
                pkt_buffer.append(pkt)

                # Handle Thread Timing
                sync = True

                # Send Packet and Increment Sequence
                udt.send(pkt, sock, RECEIVER_ADDR)
                seq += 1

            # Delay Mutex for sister thread
            time.sleep(SLEEP_INTERVAL)

        # Prepare & Send END packet
        with mutex:
            pkt = packet.make(seq, "END".encode())            # Prepare last packet
            pkt_buffer.append(pkt)
            udt.send(pkt, sock, RECEIVER_ADDR)                # Send EOF
            alive = false

# Receive thread for stop-n-wait
def receive_snw(sock, pkt):

    # Shared Resource Access
    global sync, alive

    # Spin lock to synchronize execution
    while not sync:
        continue

    # While Packets still exist
    while pkt_buffer:

        # Manually lock
        mutex.acquire()

        # Debugging info
        print("[I] RECV - Acquired Lock")

        # Retry Delay
        timer.start()

        # Get Packet
        p = pkt.pop()

        # R
        retry = RETRY_ATTEMPTS
        while retry:
            try:
                # Try ACK Check
                ack, recvaddr = udt.recv(sock)

                # If received, cleanup and pass baton
                timer.stop()
                mutex.release()
                time.sleep(SLEEP_INTERVAL)
                retry = RETRY_ATTEMPTS
                break

            except BlockingIOError:

                # Otherwise, check timer and restart
                if timer.timeout():
                    retry -= 1
                    udt.send(p, sock, RECEIVER_ADDR)
                    timer.start()

    # Remove name from hat
    alive = False

    # Mutex is held on purpose to ensure
    # Data misordering at fail doesn't occur

# Send using GBN protocol
def send_gbn(sock, filename):
    #Global Vars for comms with receiver
    global base
    global mutex
    global timer
    global PACKET_SIZE
    global RETRY_ATTEMPTS
    retries = 0

    #starts ACK receiver thread
    _thread.start_new_thread(receive_gbn, (sock,))


    #print("in send") #DEBUG
    
    
    #Reads all contents of the file and stores into a list
    #of sliced up packets
    seq = 0 
    pktBuffer = [] 
    print("opening empty text")
    with open(filename, "rb") as file:
        data = file.read(PACKET_SIZE)
        while data:
            #print("adding seq:%d" %(seq)) #DEBUG
            pktBuffer.append(packet.make(seq, data))
            seq = seq+1
            data = file.read(PACKET_SIZE)


    #print("packets added to buffer") #DEBUG
    buffSize = seq  
    index = 0
    winSize = min(WINDOW_SIZE, buffSize - base) #Ensure Window size doesnt go out of bounds
    retries = 0
    
    
    #while lowest value in the window hasn't traversed packet buffer
    while (buffSize > base):
        #print("base:%s, buffSize:%s" %(base,buffSize)) #DEBUG
        mutex.acquire()
        #print("MUTEX TAKEN") #DEBUG


        #Send packets in window sized segments
        while (index < winSize+base): 
            udt.send(pktBuffer[index], sock, RECEIVER_ADDR)
            print("Sent Packet:%s"%(index)) #DEBUG
            index = index+1

        #If timer was stopped by receive or a previous timed out: restart it for the timeout
        if not timer.running():
            timer.start()
            #print("Timer Started")  #DEBUG

        #If timer has not timed out or been stopped by ACK receiver, wait for a timeout
        #for the current window
        while not timer.timeout() and timer.running():
            mutex.release()
            #print("MUTEX RELEASED")  #DEBUG
            time.sleep(TIMEOUT_INTERVAL)
            mutex.acquire()
            #print("MUTEX TAKEN") #DEBUG

        if timer.timeout():         #If timeout, retransmit entire frame
            retries = retries+1  
            index = base
            timer.stop()
            #print("timeout, resend") #DEBUG

        else: #Transmission is fine, prepare window for next batch
            winSize = min(WINDOW_SIZE, buffSize - base)
            retries=0 #reset retries since ACKS are fine
            #print("Moving on to next set of packets") #DEBUG
        #print("MUTEX RELEASED") #DEBUG

        #if packet has been sent 10 times without an ACK, just assume it made it. 
        #Used to account for scenarios where receiver ends early
        if retries >= 10: 
            #print("retry maxed, sending n+1 pkt") #DEBUG
            base=base+1 #try this out??
            udt.send(pktBuffer[index], sock, RECEIVER_ADDR)
            retries = 0


        mutex.release() 
        #print("index:%d" %(index)) #DEBUG


    #For safety, send FIN packet 5 times at the end of comms
    #Currently at a 0.00032 failure rate
    for i in range(0,5):
        print("sending final ACK")
        FIN = packet.make(seq, "END".encode())
        udt.send(FIN, sock, RECEIVER_ADDR)



# Receive thread for GBN
def receive_gbn(sock):
    #global vars for comms with sender
    global mutex
    global base
    global timer

    #print("in receive") #DEBUG

    #Check for incoming ACKS
    while True:
        pkt,senderAddress = udt.recv(sock); #get packet and address of sender (currently only packet is needed)
        ack,ackData = packet.extract(pkt)   #Get ACK # and data. data is unused (as there should only be a confirmed ack #)
        #print("got ack") #DEBUG

        #For each confirmed ack (that is relevant), move the base up
        if (base <= ack):
            print("ack is relevant") #DEBUG
            mutex.acquire() #Stops sending to update base
            base = ack+1    #scoot up base on each successful ACK
            timer.stop()    #stop timer since ack made it back in time
            mutex.release() #Lets Sender continue working


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
    #sock.setblocking(0)
    sock.bind(SENDER_ADDR)

    #print("pre") #DEBUG

    base = 0
    filename = args.path


    if args.method == 'snw':
        sock.setblocking(0)
        _thread.start_new_thread(send_snw, (sock,))
        time.sleep(1)
        _thread.start_new_thread(receive_snw, (sock,))
        # problem with alive and sync on recv
        while alive:
            continue
    elif args.method == 'gbn':
        send_gbn(sock, filename)
    else:
        sys.stderr.write("Protocol selection must be one of [\'snw\', \'gbn\']\n")
        sys.stderr.flush()


    # problem with alive and sync on recv
    #while alive:
    #    continue

    #print("post") #DEBUG
    sock.close()

