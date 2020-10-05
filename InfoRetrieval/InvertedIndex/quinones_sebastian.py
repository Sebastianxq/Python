import os
import re
import sys
from nltk.stem import PorterStemmer

index = {} #global dict for storing words

def normalization(word):
	ps = PorterStemmer()

	table = str.maketrans(dict.fromkeys(" ,.;:'()“”% ")) #key used to remove punctuation from words
	word = word.lower()          #turns all letters lowercase
	word = word.translate(table) #removes punctuation that doesnt need to be replaced with a space
	word = word.strip('"') 		 #removes quotations
	word = word.replace('-', ' ')   #other special character cases
	word = word.replace('---', ' ')

	word = ps.stem(word) #Stems words (Cuts off prefix and suffix)

	return word               


#Appends input file words' to the global Inverted Index
def indexGenerator(inputFile):
	global index #brings index in-scope
	with open(inputFile, "r") as file:
		fileNum = inputFile[5:7] #value for the dictionary
		#print(fileNum) #DEBUG
		for line in file:    
			for word in line.split():
				word = normalization(word) #Cleans up word
				#print(word) #DEBUG
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

#runs queries on Invertes Index
def queryCheck(filename):
	queryFile = open(filename,"r")
	queries = queryFile.readlines() 
	answerFile = open("answer.txt", "w")
	queryValue = 1
	for query in queries:
		queryParts = query.split()

		#Based on query, run the required algorithm
		if queryParts[1] == "AND":
			#print("queryPart is %s"%(queryParts[1]))
			answer = andAlgorithm(queryParts[0],queryParts[2])
			print("#%d Query %s Results: %s\n" %(queryValue, query, answer))
			answerFile.write("#%d Query %s Results: %s\n" %(queryValue, query, answer))
			queryValue+=1
		else:
			#print("queryPart is %s"%(queryParts[1]))
			answer = orAlgorithm(queryParts[0],queryParts[2])
			answer.sort(key=lambda x:x[1]) #Sorts documents in ascending order
			print("#%d Query %s Results: %s\n" %(queryValue, query, answer))
			answerFile.write("#%d Query %s Results: %s\n" %(queryValue, query, answer)
			queryValue+=1
	
	queryFile.close()
	answerFile.close()

#returns documents where both words are present
def andAlgorithm(word1, word2):
	global index

	#If either word doesnt have a posting available, automatically cancel
	#Note: Both lists must also be ordered as per the algorithm requirements
	try:
		p1 = index[word1.lower()]
		p2 = index[word2.lower()]
		p1.sort(key=lambda x:x[1])
		p2.sort(key=lambda x:x[1])
		#print("word1 %s \t posting1:%s" %(word1, p1)) #DEBUG
		#print("word2 %s \t posting2:%s" %(word2, p2)) #DEBUG
	except:
		print("%s or %s not found in index" %(word1,word2)) #DEBUG
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


#Returns documents where at least one word is present
def orAlgorithm(word1, word2):
	global index
	answer = []
	p1Index = 0
	p2Index = 0

	#Split up into 2 tries in the event that one posting is empty but the other isn't
	try:
		p1 = index[word1.lower()]

		#All values in p1 are valid
		while p1Index < len(p1):
			if p1[p1Index] not in answer: 
				answer.append(p1[p1Index])
			p1Index+=1
		p2 = index[word2.lower()]
		#All values in p2 are valid
		while p2Index < len(p2):
			if p2[p2Index] not in answer: 
				answer.append(p2[p2Index])
			p2Index+=1
		#print("word1 %s \t posting1:%s" %(word1, p1)) #DEBUG
		#print("word2 %s \t posting2:%s" %(word2, p2)) #DEBUG
	except:
		print("%s not found in index" %(word1)) #DEBUG

	try:
		p2 = index[word2.lower()]
		#All values in p2 are valid
		while p2Index < len(p2):
			if p2[p2Index] not in answer: 
				answer.append(p2[p2Index])
			p2Index+=1
		#print("word1 %s \t posting1:%s" %(word1, p1)) #DEBUG
		#print("word2 %s \t posting2:%s" %(word2, p2)) #DEBUG
	except:
		print("%s not found in index" %(word2)) #DEBUG
	



	#if both lists were succesfully traversed and no match was made for query, return -1
	if answer ==[]:
		return -1
	return answer

# Main function
if __name__ == '__main__':
	dirName = "data/" #Later make this an input
	files = getAllFiles(dirName)
	queryFile = "stemmedQuery.txt"
	#print(files) #DEBUG

	#Iterates through files and stores in Inverse Index
	for file in files:
		indexGenerator(dirName+file)
	indexOutput()

	queryCheck(queryFile)
	
	#print(index) #DEBUG