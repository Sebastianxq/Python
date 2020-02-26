#!/usr/bin/python3

def premutation(fileLine):

	if (len(fileLine)==1):	
		return [fileLine]

	
	premutationList = []

	#generates premutations
	for i in range(len(fileLine)): 
		temp = fileLine[i] 
		
		# remaining list 
		remainingWords = fileLine[:i] + fileLine[i+1:] 
		
		for p in premutation(remainingWords): 
			premutationList.append([temp] + p) 

	return premutationList

def circulatShift(fileLine):
	premutationList = []
	
	#generate premutations
	for i in range(len(fileLine)): 

		#generates all cyclic possibilies
		combined = fileLine[i:]+fileLine[:i]
		premutationList.append(combined)

	return premutationList

def readAndSortFile():
	filepath = input("What is the name of your file? ") 
	try:
		with open(filepath) as fileReader:
			line = fileReader.readline()

			premutationList = []

			#iterates through file line by line
			while line:
				wordArr = line.split()

				#appends premuations to the list
				premutationList+=circulatShift(wordArr)

				#prepare next line
				line = fileReader.readline()

			# Sorting list in case-insensitive manner
			finalSort = sorted(premutationList, key = lambda s: s[0][0][0].casefold()) 

			#Converts list into a string sentence
			tempString = ""
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
