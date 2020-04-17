#!/usr/bin/env python3
#Get all cyclomatic complexities
#Find a way to export into a csv file
#Model it using excel or something

#1.)Who has removed the most lines of code? Have they added more code than they have removed?

# Store each unique name in a key value data structure
# ON each occurance, add total lines of code removed
# PUll the key that has the highest value 
# Do the same thing but look for the same user and add the added lines
#
#




from pydriller import RepositoryMining

#project_url = 'https://github.com/NationalSecurityAgency/ghidra.git'

#Used for debugging since the actual repo is WAY too big hehe
project_url = 'https://github.com/Sebastianxq/python.git'


avgLinesOfCode=0
users = {}

#syntax
#dict.update(newkey = 'value')
count = 0


for commit in RepositoryMining(project_url).traverse_commits():
	for m in commit.modifications:
		count += m.added
		if (commit.author.name not in users):
			print("only here once")
			print (commit.author.name)
			name = str(commit.author.name)
			linesAdded = m.added
			userAdd = {commit.author.name: m.added}
			users.update(userAdd)
		else:
			temp = users[commit.author.name]
			temp += m.added
			users[commit.author.name] = temp
			
		
print("done with loop")
print(users)
print("count is: ",count)

