#!/usr/bin/env python3
#Takes in a commit hash and returns the code associated with that hash
#Hash in question is a hash marked with a cyclomatic complexity of 2041 and I was curious to see what that looks like lol
from pydriller import RepositoryMining

project_url = 'https://github.com/NationalSecurityAgency/ghidra.git'

hash = "2df81f803b99e0900c298f0213dfb7d0911052b1"
count = 0
avgLinesOfCode=0
CommitList = []

with open("codeSegment.txt",'w') as myfile:
	for commit in RepositoryMining(project_url).traverse_commits():
		for m in commit.modifications:
			if (commit.hash == hash):
			 	myfile.write(m.source_code)

myfile.close()
