#! /usr/bin/env python3
import sys              #cmd line args
import re               #regex tools
import os               #for checking if file is found
import subprocess       # for executions
import string           #for string manipulation


if len(sys.argv) is not 3:
    sys.exit("ERROR: Correct usage of wordCount is wordCount.py <input file> <output file>")

#cmds used for debugging----------------------------------------------
#final Check  >>> python3 wordCountTest.py declaration.txt decOut.txt declarationKey.txt
#newWordCount >>> python3 wordCount.py declaration.txt decOut.txt
#---------------------------------------------------------------------------------

#Known Issues---------------------------------------------------------------------
#2.)Declaration.txt results in a 0.2% error rate due to a micmatch for "that", 12 found instead of 13

#read input from cmd line
inputFile = sys.argv[1]
outputFile = sys.argv[2]

wordArr = {} #init dict
table = str.maketrans(dict.fromkeys(" ,.;: ")) #key used to remove punctuation from words

#opens file and starts counting words, storing within a dictionary as <key><value>
with open(inputFile,'r') as f:
    for line in f:
        for word in line.split():

            word = word.translate(table) #removes most punctuation 
            word = word.lower()          #turns all letters lowercase
            word = word.replace('"', '') #removes quotations from words

            if "-"  in word: #splits hyphenated words
                wordList = word.split("-")
                if wordList[0] in wordArr:
                    wordArr[wordList[0]] += 1
                else:
                    if wordList[0] != "":
                        wordArr[wordList[0]] = 1
                if wordList[1] in wordArr and wordList[1] != "\n":
                    wordArr[wordList[1]] += 1
                else:
                    if wordList[1] != "" :
                        wordArr[wordList[1]] = 1
                        
            elif "'"  in word:  #splits concatenated words
                wordList = word.split("'")
                if wordList[0] in wordArr:
                    wordArr[wordList[0]] += 1
                else:
                    wordArr[wordList[0]] = 1
                if wordList[1] in wordArr:
                    wordArr[wordList[1]] += 1
                else:
                    wordArr[wordList[1]] = 1

            else: #any other word
                if word in wordArr:
                    wordArr[word] += 1
                else:
                    wordArr[word] = 1


#opens outfile file and stores dict
output = open(outputFile, "w")
for key,value in sorted(wordArr.items()):
    arrLine = (str(key)+" "+str(value)+"\n")
    output.write(arrLine)
