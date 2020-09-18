#enhancedEmail.py

This program utilizes the socket library to send a simple email over smtp, specifically utilizing UTEP's smtp server. If you do not have access to the UTEP network then you will be unable to use this program!



#enhancedGmail.py

This program is similar to enhancedEmail except it utilizes google's gmail smtp server in order to send the email. Note this currently requires that you hardcode your username and password. A function that I will likely remove by having a stdin reader instead later down the line. 


Both of the programs above can be ran utilizing the following syntax

	python3 foo.bar