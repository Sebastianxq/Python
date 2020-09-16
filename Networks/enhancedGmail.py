from socket import *
import ssl
import base64

serverName = 'smtp.gmail.com'
serverPort = 587
sock = socket(AF_INET, SOCK_STREAM)
sock.connect((serverName, serverPort))


def sendAndReceive(msg, currSock):
	currSock.send(msg.encode())
	msgReturn = currSock.recv(1024)
	print(msgReturn.decode()+'\n')

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
print("send username")
use = ("B64_ACCOUNTNAME_HERE \r\n")
sendAndReceive(use,secSock)

#send password in already formatted b64
print("send pw")
pw = ("B64_PASSWORD_HERE \r\n")
sendAndReceive(pw,secSock)


#Sender info
fwd = "mail from: <GMAIL_HERE@gmail.com>\r\n"
sendAndReceive(fwd,secSock)

#Recipient Info
rcpt = "rcpt to: <UTEP_HERE@miners.utep.edu>\r\n"
sendAndReceive(rcpt,secSock)

#Begin mail
dataReq = "data\r\n"
sendAndReceive(dataReq,secSock)

#Mail contents
email = 'subject: Testing google python script\r\n' + 'This is a scripted email\r\n' + '.\r\n'
sendAndReceive(email,secSock)