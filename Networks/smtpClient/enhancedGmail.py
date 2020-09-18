from socket import *
import ssl
import base64

#Setup information about server
serverName = 'smtp.gmail.com'
serverPort = 587
sock = socket(AF_INET, SOCK_STREAM)
sock.connect((serverName, serverPort))


#sends a msg and returns the response to stdout
def sendAndReceive(msg, currSock):
	currSock.send(msg.encode())
	msgReturn = currSock.recv(1024)
	print(msgReturn.decode()+'\n')

def convertTob64(word):
	byteForm = word.encode('ascii') #encodes word in bytes
	b64Bytes = base64.b64encode(byteForm) #encodes bytes into b64
	return b64Bytes.decode('ascii') #returns b64 as a str

#Init response, confirms connection
first = sock.recv(1024)
first.decode()
print(first.decode())


#Send helo
helo = 'helo smtp.gmail.com\r\n'
sendAndReceive(helo,sock)


#Send starttls request
tls = 'starttls\r\n'
sendAndReceive(tls,sock)


#prep socket to use ssl
secSock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv23)
auth = ('auth login\r\n')
sendAndReceive(auth,secSock)


#send username in already formatted b64
#print("send username") DEBUG
username = input("Enter Your Gmail:")
b64Username = convertTob64(username)
use = (b64Username+" \r\n")
sendAndReceive(use,secSock)


#send password in already formatted b64
password = input("Enter your password:")
b64Password = convertTob64(password)
pw = (b64Password + " \r\n")
sendAndReceive(pw,secSock)


#Sender info
fwd = "mail from: <"+username+">\r\n"
sendAndReceive(fwd,secSock)


#Recipient Info
recip = input("Who would you like to send the email to?")
rcpt = "rcpt to: <"+recip+">\r\n"
sendAndReceive(rcpt,secSock)


#Begin mail
dataReq = "data\r\n"
sendAndReceive(dataReq,secSock)


#Mail contents
email = 'subject: Testing google python script\r\n' + 'This is a scripted emai with fixed b64\r\n' + '.\r\n'
sendAndReceive(email,secSock)