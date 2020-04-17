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

project_url = 'https://github.com/NationalSecurityAgency/ghidra.git'

#Used for debugging since the actual repo is WAY too big hehe
#project_url = 'https://github.com/Sebastianxq/python.git'

users = {}


for commit in RepositoryMining(project_url).traverse_commits():
	for m in commit.modifications:
		if (commit.author.name not in users):
			userEntry = {commit.author.name: m.removed}
			users.update(userEntry)
		else:
			temp = users[commit.author.name]
			temp += m.removed
			users[commit.author.name] = temp
			
lowScore = 0
winningUser = ""
for key in users:
	if(lowScore < users[key]):
		winningUser = key
		lowScore = users[key]

print(winningUser," has removed a total of ", lowScore, "lines of code")

highScore = 0
for commit in RepositoryMining(project_url).traverse_commits():
	for m in commit.modifications:
		if (commit.author.name == winningUser):
			highScore += m.added

print(winningUser," has added a total of ", highScore, "lines of code")
