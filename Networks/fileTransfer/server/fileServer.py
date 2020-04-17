#! /usr/bin/env python3
# udp demo -- simple select-driven uppercase server

# Eric Freudenthal with mods by Adrian Veliz
import sys
import os
import random
from socket import *
from select import select


serverAddr = ("", 50000)   # any addr, port 50,000

def verifyFile(sock):
  "run this function when sock has rec'd a message"
  fileName, clientAddrPort = sock.recvfrom(100)
  print("from %s: rec'd '%s'" % (repr(clientAddrPort), repr(fileName)))
  AckFile = fileName.decode()+" ACK"
  storedName = str(verifyName(fileName.decode()))

  print ("Storing file as:"+ str(storedName))
  f= open(storedName,"w+")
  
  sock.sendto(AckFile.encode(), clientAddrPort)

def verifyName(fileName):
  #splits packet's header and payload
  packetList = fileName.split(',')
  fileName = packetList[2]
  
  filePath = './%s' % (fileName)
  fileExists=os.path.isfile(filePath)
  if (fileExists):
    newFileName = fileName.replace(".","_"+str(random.randint(0,100))+".")
    return newFileName
  else:
    return fileName

supperServerSocket = socket(AF_INET, SOCK_DGRAM)
supperServerSocket.bind(serverAddr)
supperServerSocket.setblocking(False)

# map socket to function to call when socket is....
readSockFunc = {}               # ready for reading
writeSockFunc = {}              # ready for writing
errorSockFunc = {}              # broken

timeout = 3                     #Allocates 3 seconds before failing each connection

# function to call when upperServerSocket is ready for reading
readSockFunc[supperServerSocket] = verifyFile

print("ready to receive")
timeoutNum = 0
while 1:
  readRdySet, writeRdySet, errorRdySet = select(list(readSockFunc.keys()),
                                                list(writeSockFunc.keys()), 
                                                list(errorSockFunc.keys()),
                                                timeout)
  
  if not readRdySet and not writeRdySet and not errorRdySet:
    print("timeout: no events")
    timeoutNum+=1
  if timeoutNum == 5:
    print("Timeout limit reached, disconnecting")
    break
  for sock in readRdySet:
    timeoutNum = 0 
    readSockFunc[sock](sock)

