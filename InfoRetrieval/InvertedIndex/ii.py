import os

index = {} #global dict for storing words

def normalization(word):
	table = str.maketrans(dict.fromkeys(" ,.;: ")) #key used to remove punctuation from words
	word = word.lower()          #turns all letters lowercase
	word = word.translate(table) #removes most punctuation 
	word = word.replace('"', '') #removes quotations from words
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
				normalization(word) #Break this up later
				if word not in index:

					#Overwrites instead of appends
					index[word] = (fileNum,)
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

# Main function
if __name__ == '__main__':
	dirName = "data/" #Later make this an input
	files = getAllFiles(dirName)
	#print(files) #DEBUG
	for file in files:
		indexGenerator(dirName+file)
	print(index)