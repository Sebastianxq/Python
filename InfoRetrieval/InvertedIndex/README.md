# Purpose of this file
This file is intended to created an Inverted Index of a given set of documents. 
Afterwards, the program will utilize that inverted index to efficiently solve certain queries related to that document

#How do I run this file?
In order to run the file, you will first need to ensure that you have NTLK installed, have a query.txt file that has already been stemmed utilizing the NTLK Porter Stemmer and have a set of documents that you would like to analyze within the a subdirector of your current working directory. Assuming you have everything minsu the NTLK library ready to go you can run this program using the following commands

`pip3 install NTLK`
`python3 quinones_sebastian.py`


#Will you ever make this program more robust?
Hmmmm....nah. There are certain aspects of this program that make it somewhat rigid in terms of useability (Notably: having to stem the queries and having to hardcode the text files that you want to use) but it wouldn't serve any real benefit to handle this sort of technical debt. 

#What if I wanted to use your file and fix it myself?
As will all programs in this directory: you are free to use them under the guidelines of the GNU GPL v3.0 License.
