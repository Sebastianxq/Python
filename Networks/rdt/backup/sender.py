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
RETRY_ATTEMPTS = 20


#Shared Resources for multithreading
base = 0 #AKA Min
mutex = _thread.allocate_lock() #Allows Thread to work/take a break
timer = Timer(TIMEOUT_INTERVAL) #Needed for retransmissions
pkt_buffer = []

# RELAY CONTROL
threads = 0
sync = False

# Send using Stop_n_wait protocol
def send_snw(sock): #mod sndr by Jennifer
    global threads, sync
    threads += 1 #Put name in hat
    seq = 0 #Tracks pkt count

    # Open local stream
    with open(filename, "r") as f:
        data = True #Do While Trick
        while data: 
            with mutex: #Lock Context
                print("1 - Acquired w/ {}".format(seq+1)) #DEBUG

                # Generate Packet & Link Buffer
                data = f.read(PACKET_SIZE).encode()
                pkt = packet.make(seq, data)
                pkt_buffer.append(pkt)

                sync = True #Handles Thread timing

                # Send Packet and Increment Sequence
                udt.send(pkt, sock, RECEIVER_ADDR)
                seq += 1

            # Delay Mutex for sister thread
            time.sleep(SLEEP_INTERVAL) 

        # Prepare & Send END packet
        with mutex:
            pkt = packet.make(seq, "END".encode())         
            pkt_buffer.append(pkt)
            udt.send(pkt, sock, RECEIVER_ADDR)                

    threads -= 1 #Remove name from hat

# Receive thread for stop-n-wait
def receive_snw(sock, pkt): #Mod rcvr by Jennifer
    global threads, sync
    threads += 1 #Put name in hat

    while not sync: #Spin Lock to Synchronize Execution
        continue

    while pkt_buffer: #While Packets still need to be sent
        mutex.acquire() #Lock
        print("2 - Acquired") #DEBUG

        timer.start() #Restart TTL
        p = pkt.pop() #Get next pkt

        #Checks for final ACK
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
    threads -= 1 #Remove name from hat
   
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



		#If timer was stopped by receive or timed out
		if not timer.running():
			timer.start()
			#print("Timer Started")  #DEBUG

		#As long as timer is still running with no timeouts
		while not timer.timeout() and timer.running():
			mutex.release()
			#print("MUTEX RELEASED")  #DEBUG
			time.sleep(TIMEOUT_INTERVAL)
			mutex.acquire()
			#print("MUTEX TAKEN") #DEBUG

		

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
	for i in range(0,3):
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

    #SNW
    #filename = sys.argv[1]
    # filename = "test3.txt"

    # print("pre")

    # base = 0

    # _thread.start_new_thread(send_snw, (sock,))
    # time.sleep(1)
    # _thread.start_new_thread(receive_snw, (sock, pkt_buffer))

    # while threads:
    #     continue

    # print("post")



    sock.close()


