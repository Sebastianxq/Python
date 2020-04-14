from pydriller import RepositoryMining

project_url = 'https://github.com/Sebastianxq/python.git'

count = 0
avgLinesOfCode=0
for commit in RepositoryMining(project_url).traverse_commits():
	for m in commit.modifications:
		print("nloc:", m.nloc, "added", m.added, "removed", m.removed, "complexity", m.complexity)
		#print("added", m.added)
		#print("removed", m.removed)
		#print("complexity", m.complexity)
	count+=1
	#print("nloc:",commit.nloc)
	#print('HAsh {}, author {}'.format(commit.hash, commit.author.name))

#for commit in RepositoryMining(project_url).traverse.commits():
#	for m in commit.modifications:
#		print("nloc:", commit.nloc)
print("Total number of commits:",count)


