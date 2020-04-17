#!/usr/bin/env python3
from pydriller import RepositoryMining  #Used to pull commit info
import operator							#Used to add tuple values

project_url = 'https://github.com/NationalSecurityAgency/ghidra.git'

#Used for debugging since the actual repo is WAY too big hehe
#project_url = 'https://github.com/Sebastianxq/python.git'

users = {}	
winningUser = ""
linesDeleted = 0

"""
Stores LOC added/removed into a key:tuple dictionary
Key is the user whos added/removed the code
"""
for commit in RepositoryMining(project_url).traverse_commits():
	for m in commit.modifications:

		#creates an new dict key if user is new
		if (commit.author.name not in users):
			userEntry = {commit.author.name: (m.removed, m.added)}
			users.update(userEntry)
		#Updates the current tuple to reflect additional LOC
		else:
			commit_LOC_changed = (m.removed,m.added)
			currTotalLOC = tuple(map(operator.add, users[commit.author.name], commit_LOC_changed))
			users[commit.author.name] = currTotalLOC


#print("user listing is:", users) DEBUG
for key in users:
	userInfo = users[key]
	if(linesDeleted < userInfo[0]):
		linesDeleted = userInfo[0]
		winningUser = key

print(winningUser," has removed ",users[winningUser][0]," lines and added ",users[winningUser][1], "lines")
