#!/usr/bin/python3

def premutation(fileLine):
	if (len(fileLine)==1):	
		return [fileLine]
	premutationList = []
	for i in range(len(fileLine)):					# generates premutations
		temp = fileLine[i] 
		remainingWords = fileLine[:i] + fileLine[i+1:]  	# remaining list 
		for p in premutation(remainingWords): 
			premutationList.append([temp] + p) 
	return premutationList

def circulatShift(fileLine):
	premutationList = []
	for i in range(len(fileLine)): 					# generate premutations
		combined = fileLine[i:]+fileLine[:i] 			# generates all cyclic possibilies
		premutationList.append(combined)
	return premutationList

def readAndSortFile():
	filepath = input("What is the name of your file? ") 
	try:
		with open(filepath) as fileReader:
			line = fileReader.readline()
			premutationList = []
			while line: 					#iterates through file line by line
				wordArr = line.split()
				premutationList+=circulatShift(wordArr) #appends premuations to the list
				line = fileReader.readline() 		#prepare next line
			finalSort = sorted(premutationList, key = lambda s: s[0][0][0].casefold()) 
			tempString = "" 				#Converts list into a string sentence
			for i in finalSort:
				for word in i:
					tempString+=word + " "
				print(tempString)
				tempString=""
	except FileNotFoundError:
		print("The file specified does not exist, please try again")
		
def main():
	readAndSortFile()
	
if __name__== "__main__":
  main()
