# receiver.py - The receiver in the reliable data transer protocol
import packet
import socket
import sys
import udt

RECEIVER_ADDR = ('localhost', 8080)

# Receive packets from the sender w/ SR protocol
def receive_sr(sock, windowsize):
    # Fill here
    return

#Working version of GBN 10-5-2020
def receive_gbn(sock):
    initSeq = 0
    seqList = [] #Holds Sequence numbers prev received
    f = open("gbn_receiver.txt", "w")
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

# Receive packets from the sender w/ Stop-n-wait protocol
def receive_snw(sock): #Mod rcvr SNW by Jennifer
    endStr = ''
    _seq = -1
    while True:
        pkt, senderaddr = udt.recv(sock)
        seq, data = packet.extract(pkt)
        if _seq != seq:
            _seq = seq
            endStr = data.decode()
            #sys.stderr.write("From: {}, Seq# {}\n".format(senderaddr, seq))
            #sys.stderr.flush()
            if endStr == 'END':
                return
            sys.stdout.write(endStr)
            sys.stdout.flush()
        udt.send(b' ', sock, ('localhost', 9090))

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

    #SNW (Does not work with GBN)
    #receive_snw(sock)

    receive_gbn(sock)
    
    # Close the socket
    sock.close()