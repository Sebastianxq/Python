#! /usr//bin/env python3
# udp demo client.  Modified from Kurose/Ross by Eric Freudenthal 2016

from socket import *
import os
import sys, re
import math
from select import select
# default params
serverAddr = ('localhost', 50000)
clientAddr = ("", 50001) #any address but port 50001

def usage():
    print("usage: %s [--serverAddr host:port]"  % sys.argv[0])
    sys.exit(1)

try:
    args = sys.argv[1:]
    while args:
        sw = args[0]; del args[0]
        if sw in ("--serverAddr", "-s"):
            addr, port = re.split(":", args[0]); del args[0]
            serverAddr = (addr, int(port)) # addr can be a string (yippie)
        else:
            print("unexpected parameter %s" % args[0])
            usage();
except:
    usage()

print("serverAddr = %s" % repr(serverAddr))
clientSocket = socket(AF_INET, SOCK_DGRAM)

def fileTransfer(sock):
    print("Input file name. Format: foo.extension")
    fileName = sys.stdin.readline()[:-1]     # delete final \n

    #should move these into a different method to clean up later
    filePath = './%s' % (fileName)
    fileExists=os.path.isfile(filePath)
    fileSize = os.path.getsize(filePath)
    totalPackets = str(math.ceil(fileSize/10))
    filenamePacket = 'f,'+totalPackets+","+fileName
    
    if (fileExists):
        print(filenamePacket) 
        clientSocket.sendto(filenamePacket.encode(), serverAddr)
        fileAck, serverAddrPort = clientSocket.recvfrom(100)
        print('fileAck from %s is "%s"' % (repr(serverAddrPort), fileAck.decode()))
    else:
        print ("file not found, exiting program")

#a socket for incoming connections to use, the client
supperClientSocket = socket(AF_INET, SOCK_DGRAM)
supperClientSocket.bind(clientAddr)
supperClientSocket.setblocking(False)

# map socket to function to call when socket is....
readSockFunc = {}               # ready for reading
writeSockFunc = {}              # ready for writing
errorSockFunc = {}              # broken

timeout = 3                     #Allocate 3 seconds before failing
timeoutNum = 0                  #total num timeouts, init 0
# functions to be called for each respective socket
#readSockFunc[supperClientSocket] = fileTransfer
writeSockFunc[supperClientSocket] = fileTransfer

while 1:
  readRdySet, writeRdySet, errorRdySet = select(list(readSockFunc.keys()),
                                                list(writeSockFunc.keys()), 
                                                list(errorSockFunc.keys()),
                                                timeout)
  
  if not readRdySet and not writeRdySet and not errorRdySet:
    print("Client timeout: no events")
    timeoutNum+=1
  if timeoutNum == 5:
    print("Client timeout limit reached, disconnecting")
    break

  for sock in readRdySet:
    #would read be needed for this scenario?
    print("in readySet")
    #readSockFunc[sock](sock) #(sock) is an arg?
    timeoutNum = 0
  for sock in writeRdySet:
      #change based on what the result was?
      #or deal with that within the actual method itself?
      writeSockFunc[sock](sock)
  for sock in errorRdySet:
      print("in errorSet")





      
#deprecated code that might be useful later on during development
#fileSize = os.path.getsize(filePath)
