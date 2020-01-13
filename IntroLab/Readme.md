# How to Run
This program was coded in Python 3. In order to run the program go to your terminal and type in a command similar to the following

`$ python wordCount.py inputFile.txt outputFile.txt`


# Purpose 
This program was intended to be an introduction into python, it keeps track of the total the number of times each word occurs in a text file and has the following characteristics
* excludes white space and punctuation
* is case-insensitive
* prints out to the output file (overwriting if it exists) the list of
  words sorted in descending order with their respective totals
  separated by a space, one word per line.


# Additional Notes
To test your program we provide wordCountTest.py and two key
files. This test program takes your output file and notes any
differences with the key file. An example use is:

`$ python wordCountTest.py declaration.txt myOutput.txt declarationKey.txt`

While the wordCount program was created by me the test file was created by Dr. Freudenthal at the University of Texas at El Paso. He reserves all rights to the code.
