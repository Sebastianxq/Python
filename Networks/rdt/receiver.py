# receiver.py - The receiver in the reliable data transer protocol
import packet
import socket
import sys
import udt

RECEIVER_ADDR = ('localhost', 8080)

# Receive packets from the sender w/ GBN protocol
def receive_gbn(sock):
    #upon each receival send an ACK back
   dataStr = ''
   seqList = []
   f = open("gbn_receiver.txt", "w")
   while dataStr!='END':
       pkt, senderaddr = udt.recv(sock)
       seq, data = packet.extract(pkt)

       #Does not write if duplicate pkt or FIN pkt 
       print("data is "+data.decode())
       if (seq not in seqList and not data.decode() == "END"):
          f.write(data.decode())

       seqList.append(seq)
       dataStr = data.decode()
       print("From: ", senderaddr, ", Seq# ", seq, dataStr) #debug
       
       #Sends ACK back to sender to continue comms
       ack = packet.make(seq, "ACK".encode())
       udt.send(ack, sock, senderaddr)


      #Need a way to account for duplicate ACKS
   f.close()

# Receive packets from the sender w/ SR protocol
def receive_sr(sock, windowsize):
    # Fill here
    return


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

    receive_gbn(sock)
    # Close the socket
    sock.close()