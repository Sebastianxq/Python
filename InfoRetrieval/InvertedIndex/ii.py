#Go through file 1, store in dictionary
#GO through file 2, store in dictionary, if duplicate, append to value
#...
#Done

def indexGenerator():
	index = {}
	with open("data/d1.txt", "r") as file:
		for line in file: 
			# reading each word         
			for word in line.split():
				#check if word doesnt exist and if so add it and add "d1" as the key
				if word not in index:
					index[word] = "d1"
	print(index)

    #In the future find a way to read over all the files in one loop,  
   
# Main function
if __name__ == '__main__':

	indexGenerator()