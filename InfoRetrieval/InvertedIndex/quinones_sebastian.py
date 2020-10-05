import os
import re
import sys
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize
index = {} #global dict for storing words

def normalization(word):
	ps = PorterStemmer()

	table = str.maketrans(dict.fromkeys(" ,.;:'()-“”% ")) #key used to remove punctuation from words
	word = word.lower()          #turns all letters lowercase
	word = word.translate(table) #removes most punctuation 
	word = word.strip('"') #removes special quotations from words
	word = word.replace('---', ' ') #literally for one set of words

	word = ps.stem(word) #Stems words (Cuts off prefix and suffix)

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
				print(word)
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
	#get query
	#Turn both of the words into a postings list
	#AND or OR accordingly (Using the algorithm in class)

	queryFile = open(filename,"r")
	queries = queryFile.readlines() 
	queryValue = 1
	for query in queries:
		queryParts = query.split()
		if queryParts[1] == "AND":
			answer = andAlgorithm(queryParts[0],queryParts[2])
			print("q%d: %s" %(queryValue, answer))
			queryValue+=1
		else:
			#orAlgorithm(queryParts[0],queryParts[2])
			#print("q%d: %s" %(queryValue, answer))
			queryValue+=1

def andAlgorithm(word1, word2):
	global index

	#If either word doesnt have a posting available, automatically cancel
	try:
		p1 = index[word1.lower()]
		p2 = index[word2.lower()]
	except:
		return -1

	answer = []
	p1Index = 0
	p2Index = 0
	while p1 and p2: #While that i'm definitely using wrong
		
		#Try to load the next posting, if either fails then we're done 
		try:
			p1Value = p1[p1Index]
			p2Value = p2[p2Index]
		except:
			break #one or more lists are done, loop doesnt end though

		if p1[p1Index] == p2[p2Index]: #If postings match (AND==True)
			answer.append(p1[p1Index])
			p1Index+=1
			p2Index+=1
		elif p1[p1Index][1] < p2[p2Index][1]: 	#If doc num for p1 is less than p2
			p1Index+=1
		else:									#if doc num for p2 less than p1
			p2Index+=1

	#if both lists were succesfully traversed and no match was made for query, return -1
	if answer ==[]:
		return -1
	return answer


def orAlgorithm(word1, word2):
	print("TBD")

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

	queryCheck(queryFile)