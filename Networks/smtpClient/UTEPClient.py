from socket import *


serverName = 'smtp.utep.edu'
serverPort = 25
clientSocket = socket(AF_INET,SOCK_STREAM)
clientSocket.connect((serverName,serverPort))


#Sends encoded strings over to server and prints the response
def sendAndReceive(msg):
	clientSocket.send(msg.encode())
	msgReturn = clientSocket.recv(1024)
	print(msgReturn.decode()+'\n')

#No overloading in python :(	
firstMsg = clientSocket.recv(1024)
firstMsg = firstMsg.decode()	
print(firstMsg + "\n")


#helo to start smtp
print("sending helo\n")
helo = 'helo utep.edu\r\n'
sendAndReceive(helo)


#send mail FROM request
print("sending mail FROM addr\n")
sender = 'mail from: UTEP_EMAIL@utep.edu\r\n'
sendAndReceive(sender)


#send mail TO request
print("sending mail TO addr\n")
recipient = 'rcpt to: RECIPIENT@PROVIDER.com\r\n'
sendAndReceive(recipient)

#send data request
print("sending data request\n")
dataReq = 'data\r\n'
sendAndReceive(dataReq)


#email contents 
print("sending subject line\n")
subject = 'subject: Email from my email Client\r\n\r\n' +'\n'+ 'This is a test email from my own email client. Hot it finds you well. -Quinones Sebastian\r\n' + '.\r\n'
sendAndReceive(subject)

clientSocket.close()
