#! /usr//bin/env python3
# udp demo client.  Modified from Kurose/Ross by Eric Freudenthal 2016

from socket import *
import os
import sys, re                          
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
#clientSocket = socket(AF_INET, SOCK_DGRAM)

def fileTransfer():
    print("Input file name. Format: foo.extension")
    fileName = sys.stdin.readline()[:-1]     # delete final \n
    filePath = './%s' % (fileName)
    fileExists=os.path.isfile(filePath)
    fileSize = os.path.getsize(filePath)
    fileNameAndSize = fileName+","+str(fileSize)
    print(fileNameAndSize)
    if (fileExists):
        # True, proceed with sending filename (and data in the future)
        print("file found, or something like that")
        #can use something like re.split(',') to seperate header/payload
        #head should include the following
     
        clientSocket.sendto(fileNameAndSize.encode(), serverAddr)
        fileAck, serverAddrPort = clientSocket.recvfrom(2048)
        print('fileAck from %s is "%s"' % (repr(serverAddrPort), fileAck.decode()))

    else:
        print ("file not found, exiting program")

#a socket for incoming connections to us, the client
supperClientSocket = socket(AF_INET, SOCK_DGRAM)
supperClientSocket.bind(clientAddr)
supperClientSocket.setblocking(False)

# map socket to function to call when socket is....
readSockFunc = {}               # ready for reading
writeSockFunc = {}              # ready for writing
errorSockFunc = {}              # broken

timeout = 3                     #Allocates 3 seconds before failing each connection

# function to call when upperServerSocket is ready for reading
#readSockFunc[supperClientSocket] = fileTransfer
writeSockFunc[serverAddr] = fileTransfer

#print("Type in the file that you would like to send")
timeoutNum = 0
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
    print("in readySet")
    #readSockFunc[sock](sock) #(sock) is an arg?
    timeoutNum = 0
  for sock in writeRdySet:
      print("write tst")
      writeSockFunc[serverAddr](serverAddr)
  for sock in errorRdySet:
      print("in errorSet")
