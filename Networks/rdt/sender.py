import socket
import sys
# import _thread
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

# You can use some shared resources over the two threads
# base = 0
# mutex = _thread.allocate_lock()
# timer = Timer(TIMEOUT_INTERVAL)

# Need to have two threads: one for sending and another for receiving ACKs

# Generate random payload of any length
def generate_payload(length=10):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str


# Send using Stop_n_wait protocol
def send_snw(sock):
	# Fill out the code here
    seq = 0
    while(seq < 20):
        data = generate_payload(40).encode()
        pkt = packet.make(seq, data)
        print("Sending seq# ", seq, "\n")
        udt.send(pkt, sock, RECEIVER_ADDR)
        seq = seq+1
        time.sleep(TIMEOUT_INTERVAL)
    pkt = packet.make(seq, "END".encode())
    udt.send(pkt, sock, RECEIVER_ADDR)

#Modifed Send and Wait method
#Packets send identically to send_snw function
def mod_snw(sock):
	seq = 0

	#Opens file and reads first 512 bytes to get the ball rolling
	#From there, sends those 512 and reads another 512 bytes
	#Once file is emptied, sends FIN Packet
	with open("helloFr1end.txt", "rb") as file:
		data = file.read(512)
		while data:
			pkt = packet.make(seq, data)
			print("Sending seq ", seq, "\n")
			udt.send(pkt, sock, RECEIVER_ADDR)
			seq = seq+1
			time.sleep(TIMEOUT_INTERVAL)
			data = file.read(512)
		
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
		pkt = packet.make(seq, data)
		print("Sending seq ", seq, "\n")
		udt.send(pkt, sock, RECEIVER_ADDR)
		seq = seq+1
		time.sleep(TIMEOUT_INTERVAL)
	#Signifies end of comms
	pkt = packet.make(seq, "END".encode())
	udt.send(pkt, sock, RECEIVER_ADDR)

# Receive thread for stop-n-wait
def receive_snw(sock, pkt):
    # Fill here to handle acks
    return

# Send using GBN protocol
def send_gbn(sock):

    return

# Receive thread for GBN
def receive_gbn(sock):
    # Fill here to handle acks
    return


# Main function
if __name__ == '__main__':
    # if len(sys.argv) != 2:
    #     print('Expected filename as command line argument')
    #     exit()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(SENDER_ADDR)

    # filename = sys.argv[1]

    #send_snw(sock)
    mod_snw(sock)
    sock.close()


