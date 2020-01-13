# Contents
Within this directory are examples of an echo server. This lab was intended to introduce the class to the select function as an alternative to threading when it came to handling multiple clients for a server. A brief explanation of each client/server code is shown below:

### UDPclient.py 
simply sends a message to the server, it will terminate after 1 message is sent.

### client2.py
sends a message to the server and then recieves the echo and modifies it by capitalizing each word, it will terminate after 1 message is sent.

### UDPserver.py
Recieves a message from a client and displays the address, port and message that was received via UDP

### UDPserver-select-1.py
Similar to UDPserver in function but modified to utilize the "select" function. Timeouts can be specified and is defaulted at 5 seconds.

# How to Run
This lab is best ran on emacs (in my opinion) but can be run on anything that allows you to run multiple shells. Run the server you would like as you would any other exectuable:

`./server.py`

and within your second shell, run the client code that you would like:

`./client.py`




# Acknowledgement
Since it has been a little under a year since I have done this lab, I will be assuming that the majority of the server code and perhaps most of the "client.py" code as well has been written by the instructor and his teaching team from the 2019 computer networks course at UTEP. 
