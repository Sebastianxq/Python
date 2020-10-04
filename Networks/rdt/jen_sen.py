import socket
import sys
import _thread
import time
import string
import packet
import udt
import random
from timer import Timer

# SETTINGS
PACKET_SIZE = 512
RECEIVER_ADDR = ('localhost', 8080)
SENDER_ADDR = ('localhost', 9090)
SLEEP_INTERVAL = 2.0 # (In seconds)
TIMEOUT_INTERVAL = 1.0
WINDOW_SIZE = 4
RETRY_ATTEMPTS = 20

# SHARED RESOURCES
base = 0
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
    global sync

    # Track packet count
    seq = 0

    # Open local stream
    with open(filename, "r") as f:
        # Do-While Trick
        data = True
        # Sequential File Access
        while data:
            # Lock Context
            with mutex:
                # Debugging Info
                print("1 - Acquired w/ {}".format(seq+1))

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

# Receive thread for stop-n-wait
def receive_snw(sock, pkt):
    global sync, alive # Shared Resource Access

    # Spin lock to synchronize execution
    while not sync:
        continue

    # While Packets still exist
    while pkt_buffer:

        # Manually lock
        mutex.acquire()

        # Debugging info
        print("2 - Acquired")

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
def send_gbn(sock):
    #Global Vars for comms with receiver
    global base
    global mutex
    global timer
    global PACKET_SIZE

    #starts ACK receiver thread
    _thread.start_new_thread(receive_gbn, (sock,))


    #print("in send") #DEBUG
    
    
    #Reads all contents of the file and stores into a list
    #of sliced up packets
    seq = 0 
    pktBuffer = [] 
    with open("test4.txt", "rb") as file:
        data = file.read(PACKET_SIZE)
        while data:
            #print("adding seq:%d" %(seq)) #DEBUG
            pktBuffer.append(packet.make(seq, data))
            seq = seq+1
            data = file.read(PACKET_SIZE)
    
    
        pktBuffer.append(packet.make(seq, "END".encode())) #Once file is stored, append FIN pkt
        seq = seq+1



    #print("packets added to buffer") #DEBUG
    buffSize = seq  
    index = 0
    winSize = min(WINDOW_SIZE, buffSize - base) #Ensure Window size doesnt overflow
    
    
    #while lowest value in the window hasn't traversed packet buffer
    while (buffSize > base):
        print("base:%s, buffSize:%s" %(base,buffSize)) #DEBUG
        mutex.acquire()
        #print("MUTEX TAKEN") #DEBUG


        #Send packets until windowSize is met
        while (index < winSize+base): 
            udt.send(pktBuffer[index], sock, RECEIVER_ADDR)
            print("Sent Packet:%s"%(index)) #DEBUG
            index = index+1

        #As long as timer is still running with no timeouts
        while not timer.timeout() and timer.running():
            mutex.release()
            #print("MUTEX RELEASED")  #DEBUG
            time.sleep(TIMEOUT_INTERVAL)
            mutex.acquire()
            #print("MUTEX TAKEN") #DEBUG


        #If timer was stopped by receive or a previous timed out
        if not timer.running():
            timer.start()
            #print("Timer Started")  #DEBUG

        #If timeout, retransmit entire frame
        if timer.timeout():
            index = base
            timer.stop()
            #print("timeout, resend") #DEBUG
        else: #Transmission is fine, prepare window for next batch
            winSize = min(WINDOW_SIZE, buffSize - base)
            #print("Moving on to next set of packets") #DEBUG
        #print("MUTEX RELEASED") #DEBUG
        mutex.release() 

        print("index:%d" %(index)) #DEBUG

        #Still not sure why only this combination helps counteract the FIN getting lost
        #Not 100% consistent however
        if index == buffSize and base==buffSize-1:
            print("in hogwarts")
            break


# Receive thread for GBN
def receive_gbn(sock):
    #global vars for comms with sender
    global mutex
    global base
    global timer

    #print("in receive") #DEBUG

    #Check for incoming ACKS
    while True:
        pkt,senderAddress = udt.recv(sock); #Address unused
        ack,ackData = packet.extract(pkt)   #Data could be checked for corruption
        #print("got ack") #DEBUG

        #Might have multiple ACKS in buffer, empty it out and iterate accordingly
        if (base <= ack):
            print("ack is relevant") #DEBUG
            mutex.acquire() #Stops sending to update base
            base = ack+1    #scoot up base on each successful ACK
            timer.stop()    #timeout expired (in a good way)
            mutex.release() #Lets Sender continue working



# Main function
if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #sock.setblocking(0)
    sock.bind(SENDER_ADDR)

    #filename = "test3.txt"
    #print("pre")
    #base = 0
    # _thread.start_new_thread(send_snw, (sock,))
    # time.sleep(1)
    # _thread.start_new_thread(receive_snw, (sock, pkt_buffer))
    # while alive:
    #     continue
    #print("post")

    #gbn stuff
    send_gbn(sock)


    sock.close()