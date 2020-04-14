#!/usr/bin/env python3
#Get all cyclomatic complexities
#Find a way to export into a csv file
#Model it using excel or something

#1.) What is the distribution of the cyclomatic complexity?

#Once the above is solved, remove non-code files from the mix!


from pydriller import RepositoryMining

#project_url = 'https://github.com/NationalSecurityAgency/ghidra.git'
project_url = 'https://github.com/Sebastianxq/python.git'


#Give a distribution of complexity based on overall
#Then sort based on file
count = 0
avgLinesOfCode=0
CommitList = []

with open("csvTest.csv",'w') as myfile:
	for commit in RepositoryMining(project_url).traverse_commits():
		for m in commit.modifications:
			commitInfo = "author "+ commit.author.name+",hash "+ commit.hash+ ",complexity,"+ str(m.complexity)
			print(commitInfo)
			myfile.write(commitInfo)
		count+=1


print("Total number of commits:",count)


myfile.close()
