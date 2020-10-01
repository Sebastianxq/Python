import socket
import sys
import _thread
import time
import string
import packet
import udt
import random
from timer import Timer

# Some already defined parameters
PACKET_SIZE = 512
RECEIVER_ADDR = ('localhost', 8080)
SENDER_ADDR = ('localhost', 9090)
SLEEP_INTERVAL = 0.05 # (In seconds)
TIMEOUT_INTERVAL = 0.5
WINDOW_SIZE = 4

#Shared Resources for multithreading
base = 0 #AKA Min
mutex = _thread.allocate_lock() #Allows Thread to work/take a break
timer = Timer(TIMEOUT_INTERVAL) #Needed for retransmissions


# Generate random payload of any length
def generate_payload(length=10):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str

# Send using Stop_n_wait protocol
#Modified Sender by jennifer
def send_snw(sock):

    # Access to shared resources
    global threads, sync

    # Put name in hat
    threads += 1

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

    # Remove name from hat
    threads -= 1

#Modifed Send and Wait method
#Packets send identically to send_snw function
def mod_snw(sock):
	seq = 0

	#Opens file and reads first 512 bytes to get the ball rolling
	#From there, sends those 512 and reads another 512 bytes
	#Once file is emptied, sends FIN Packet
	with open("helloFr1end.txt", "rb") as file:
		data = file.read(PACKET_SIZE)
		while data:
			pkt = packet.make(seq, data)
			print("Sending seq ", seq, "\n")
			udt.send(pkt, sock, RECEIVER_ADDR)
			seq = seq+1
			time.sleep(TIMEOUT_INTERVAL)
			data = file.read(PACKET_SIZE)
		
		pkt = packet.make(seq, "END".encode())
		udt.send(pkt, sock, RECEIVER_ADDR)

#Debug function. sends text file in lines rather than bytes
#Easier to send way more packets with this one (for debugging retransmission)
def lineSnW(sock):
	seq = 0
	bio = open("bio.txt", "r")
	lines = bio.readlines()
	for line in lines:
		#Send here
		data = line
		pkt = packet.make(seq, data.encode())
		print("Sending seq ", seq, "\n")
		udt.send(pkt, sock, RECEIVER_ADDR)
		seq = seq+1
		time.sleep(TIMEOUT_INTERVAL)
	#Signifies end of comms
	pkt = packet.make(seq, "END".encode())
	udt.send(pkt, sock, RECEIVER_ADDR)

# Receive thread for stop-n-wait
#Modified Receiver by Jennifer
def receive_snw(sock, pkt):

    # Shared Resource Access
    global threads, sync

    # Put Name in Hat
    threads += 1

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
    threads -= 1
   

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
	with open("test3.txt", "rb") as file:
		data = file.read(PACKET_SIZE)
		while data:
			#print("adding seq:%d" %(seq)) #DEBUG
			pktBuffer.append(packet.make(seq, data))
			seq = seq+1
			data = file.read(PACKET_SIZE)


	#List is then iterated through using some classic-
	#mergesort type variables.
	#print("packets added to buffer") #DEBUG
	buffSize = seq  
	index = 0
	winSize = min(WINDOW_SIZE, buffSize - base) #Ensure Window size doesnt overflow
	
	
	#while bottom of list hasnt reached top
	while (buffSize > base):
		#print("base:%s, buffSize:%s" %(base,buffSize)) #DEBUG
		mutex.acquire()
		#print("MUTEX TAKEN") #DEBUG


		#Iterate(Send) until windowSize is met
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


		#If timer was stopped by receive or timed out
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

	#End of comms
	#print("sending FIN pkt") #DEBUG
	pkt = packet.make(seq, "END".encode())
	udt.send(pkt, sock, RECEIVER_ADDR)


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
    		#print("ack is relevant") #DEBUG
    		mutex.acquire() #Stops sending to update base
    		base = ack+1    #scoot up base on each successful ACK
    		timer.stop()	#timeout expired (in a good way)
    		mutex.release() #Lets Sender continue working



# Main function
if __name__ == '__main__':
    # if len(sys.argv) != 2:
    #     print('Expected filename as command line argument')
    #     exit()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(SENDER_ADDR)

    # filename = sys.argv[1]

    #SNW Stuff
    #mod_snw(sock)
    #lineSnW(sock)

    #GBN Stuff
    # print("starting send")
    send_gbn(sock)

    #Test
    #good_snw(sock)



    sock.close()

