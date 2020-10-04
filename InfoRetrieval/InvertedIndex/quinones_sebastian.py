import os
import re
import sys

index = {} #global dict for storing words

def normalization(word):
	table = str.maketrans(dict.fromkeys(" ,.;:'() ")) #key used to remove punctuation from words
	word = word.lower()          #turns all letters lowercase
	word = word.translate(table) #removes most punctuation 
	word = word.replace('"', '') #removes quotations from words

	#Might have to add something that removes hyphens later.
	return word               


#Appends input file words' to the global Inverted Index
def indexGenerator(inputFile):
	global index #brings index in-scope
	with open(inputFile, "r") as file:
		fileNum = inputFile[5:7]
		#print(fileNum) #DEBUG
		for line in file:    
			for word in line.split():
				word = normalization(word) #Removes certain special chars

				if word in index: #If word already in index, ensure that we don't enter a duplicate document
					#print("word was already in index") #DEBUG
					if (fileNum not in index[word]):					
						docList = index[word] 
						docList.append(fileNum)
						index[word] = docList

				elif word not in index: #Word not in index, add automatically
					#print("word not in index") #DEBUG
					docList = [fileNum] #Initialize as a list
					index[word] = docList
					
	#print(index)


#returns a list of all files in the given directory
def getAllFiles(dirName):
	directory = os.fsencode(dirName)
	files = []
	for file in os.listdir(directory):
		files.append(file.decode())

		#filename = os.path.splitext(file)[0].decode()	#used if we just want the doc name, not the extension

	return files	   

#Outputs index contents to a file
def indexOutput():
	global index
	docStrings = ''
	#f.open("index_lastname.txt", "w")
	with open("index_quinones.txt", 'w') as file:
		for key, value in index.items():

			docStrings = ",".join(value)
			printStatement = key+"  "+docStrings+'\n'
			file.write(printStatement)	

def queryCheck(filename):
	print('gg')
	#get query
	#Turn both of the words into a postings list
	#AND or OR accordingly (Using the algorithm in class)

	queryFile = open(filename,"r")
	queries = queryFile.readlines() 
  	for query in queries:
  		queryParts = query.split()
  		if queryParts[1] == "AND":
  			andAlgorithm(queryParts[0],queryParts[2])
  		else:
  			orAlgorithm(queryParts[0],queryParts[2])

def andAlgorithm(word1, word2):
	print('gg')

def orAlgorithm(word1, word2):
	print('gg')

# Main function
if __name__ == '__main__':
	dirName = "data/" #Later make this an input
	files = getAllFiles(dirName)
	queryFile = "query.txt"
	#print(files) #DEBUG
	#Iterates through files and stores in Inverse Index
	for file in files:
		indexGenerator(dirName+file)
	indexOutput()

	#