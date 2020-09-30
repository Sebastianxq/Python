# receiver.py - The receiver in the reliable data transer protocol
import packet
import socket
import sys
import udt

RECEIVER_ADDR = ('localhost', 8080)

# Receive packets from the sender w/ GBN protocol
def receive_gbn(sock):
   seqList = [] #Holds Sequence numbers prev received
   f = open("gbn_receiver.txt", "w")
   dataStr = ''

   #While NO FIN pkt
   while dataStr!='END':
       pkt, senderaddr = udt.recv(sock)
       seq, data = packet.extract(pkt)
       dataStr = data.decode()

       #Does not write if duplicate pkt or FIN pkt 
       #print("data is "+data.decode()) #DEBUG
       if (seq not in seqList and not dataStr == "END"):
          f.write(dataStr)

       #Data recv, ensure duplicate packets are ignored
       seqList.append(seq)
       #print("From: ", senderaddr, ", Seq# ", seq, dataStr) #DEBUG

       #Send back ACK to confirm rcpt. 
       #If ACK lost, retransmission happens on sender side :)
       ack = packet.make(seq, "ACK".encode())
       udt.send(ack, sock, senderaddr)

       #TODO
       #I think instead of checking against an entire list we can
       #just have it check to see if ACK is
       #Sends ACK back to sender to confirm receipt
       #Obviously a list is unfeasible for modern comms
       #Ex.) Imagine trying to hold a list of ACKs for 512b from a 5GB file??
       #     That would be like 10 million numbers lol


   f.close() 

# Receive packets from the sender w/ SR protocol
def receive_sr(sock, windowsize):
    # Fill here
    return

def newGBN(sock):
    initSeq = 0
    seqList = [] #Holds Sequence numbers prev received
    f = open("gbn_receiver.txt", "w")
    dataStr = ''

    while dataStr!='END':
       pkt, senderaddr = udt.recv(sock)
       seq, data = packet.extract(pkt)
       dataStr = data.decode()

       #Does not write if duplicate pkt or FIN pkt 
       #print("data is "+data.decode()) #DEBUG
       if (seq == initSeq and not dataStr == "END"):
          print("packet fine, writing to file")
          f.write(dataStr)
          initSeq = initSeq+1
       elif not seq == initSeq:
            print("Not in ordered pkt received")
            ack = packet.make(initSeq, "ACK".encode())

       ack = packet.make(seq, "ACK".encode())
       udt.send(ack, sock, senderaddr)

    f.close() 
# Receive packets from the sender w/ Stop-n-wait protocol
def receive_snw(sock):
   endStr = ''
   while endStr!='END':
       pkt, senderaddr = udt.recv(sock)
       seq, data = packet.extract(pkt)
       endStr = data.decode()
       print("From: ", senderaddr, ", Seq# ", seq, endStr)

def mod_receive_snw(sock):
   endStr = ''
   f = open("bio2.txt", "w")
   while endStr!='END':
       pkt, senderaddr = udt.recv(sock)
       seq, data = packet.extract(pkt)
       endStr = data.decode()
       print("From: ", senderaddr, ", Seq# ", seq, endStr)
       if (endStr != 'END'):
        f.write(endStr)
   f.close()
# Main function
if __name__ == '__main__':
    # if len(sys.argv) != 2:
    #     print('Expected filename as command line argument')
    #     exit()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(RECEIVER_ADDR)
    # filename = sys.argv[1]
    #mod_receive_snw(sock)

    #receive_gbn(sock)
    newGBN(sock)
    # Close the socket
    sock.close()