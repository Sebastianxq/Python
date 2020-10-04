import os
import re
import sys

index = {} #global dict for storing words

def normalization(word):
	table = str.maketrans(dict.fromkeys(" ,.;:'() ")) #key used to remove punctuation from words
	word = word.lower()          #turns all letters lowercase
	word = word.translate(table) #removes most punctuation 
	word = word.replace('"', '') #removes quotations from words

	return word


	#if "-"  in word: #splits hyphenated words                    
    #elif "'"  in word:  #splits concatenated words
               

def index2():
	index = {}
	directory = os.fsencode("data")
	#print(os.path.splitext(file)[0])

	for file in os.listdir(directory):
		#print(os.path.splitext(file)[0].decode())

		filename = os.path.splitext(file)[0].decode()
		with open("data/"+filename+".txt", "r") as file:

			for line in file:          
				for word in line.split():
					print(type(word))
					#if word not in index:
					#	index[word].append(filename,)
	print(index)

def indexGenerator(inputFile):
	global index #brings index in-scope
	with open(inputFile, "r") as file:
		fileNum = inputFile[5:7]
		#print(fileNum) #DEBUG
		for line in file:    
			for word in line.split():
				word = normalization(word) #Break this up later
				#print(word)

				#Need to fix duplicate listings showing up
				if word in index:
					#print("word was already in index")
					if (fileNum not in index[word]):					
						docList = index[word]
						docList.append(fileNum)
						index[word] = docList

					#Just wontonly add the numbers instead of
					#checking first if the numbers are already there

				elif word not in index:
					#print("word not in index")
					docList = [fileNum]
					index[word] = docList
					#if (index[word] and index[word] == word):
					#	print("this should b happening")
				#might not even need to check if the word is not in the dictionary
				#if word not in index:

					#Overwrites instead of appends
					#index[word] = (fileNum,)
	#print(index)


#returns a list of all files
def getAllFiles(dirName):
	directory = os.fsencode(dirName)
	files = []
	for file in os.listdir(directory):
		files.append(file.decode())

		#used if we just want the doc name, not the extension
		#filename = os.path.splitext(file)[0].decode()	
	return files	   

def indexOutput():
	global index
	docStrings = ''
	#f.open("index_lastname.txt", "w")
	with open("index_quinones.txt", 'w') as file:
		for key, value in index.items():

			docStrings = ",".join(value)
			printStatement = key+"  "+docStrings+'\n'
			file.write(printStatement)	
			#print(*value, sep=", ")
			#sys.stdout = original_stdout

		#keyPart = str(key)
		#valuePart = str(value)
		#print(keyPart+valuePart)



# Main function
if __name__ == '__main__':
	dirName = "data/" #Later make this an input
	files = getAllFiles(dirName)
	#print(files) #DEBUG
	for file in files:
		indexGenerator(dirName+file)

	#for key, value in index.items():
	#	print(key, ' : ', value)

	indexOutput()