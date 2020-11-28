#!/usr/bin/python3

# pip install wheel
# pip install git+https://github.com/marcosfpr/match_up_lib.git
from matchup.structure.vocabulary import Vocabulary

# pip install html2text
import html2text

from urllib.request import urlopen

#pip install beautifulsoup4
from bs4 import BeautifulSoup


# Download UTEP CS faculty webpages
def indexingWebpages(listWebpages):
	# Read URLs from the listWebpages list
	for webpage in listWebpages:
		# Retrieve the webpage content
		with urlopen(webpage) as wp:
			# Reading the HTML content
			contentHTML = wp.read()

			# Extracting the content of each webpage (without HTML tags)
			# and convert it to UTF-8			
			content = html2text.html2text(str(contentHTML,'utf-8'))
			
			filename = BeautifulSoup(contentHTML, 'html.parser').find("title").text

			file = open('indexedFiles/'+filename+'.txt', "w") 
			file.write(content) 
			file.close() 

def main():
	# List of URLs. Insert the URLs of all faculty's web pages.
	listWebpages = ['http://www.cs.utep.edu/isalamah/','http://www.cs.utep.edu/kiekintveld/','http://www.cs.utep.edu/makbar/']

	# Indexing faculty webpages
	indexingWebpages(listWebpages)
	
	#===================================
	# MatchUp Information Retrieval Library
	# https://match-up-lib.readthedocs.io/en/latest/index.html
	# Description:
	# Match up is a PURE-Python library based on Information Retrieval (IR) concepts. 
	# It implements five IR models (Boolean, Vector Space, Probabilistic, Extended Boolean, Generalized Vector and Belief Network) 
	# that can be tested and compared through a collection of documents and a query. 
	# The result will be a query-based similarity rank that can be used to get insights about the collection.
	#===================================


	#===================================
	#           PREPROCESSING
	#===================================

	# Creating the data structure that represents and store all text processing
	# The first parameter is the 'path' where results are stored. In this case, the results will be stored in the folder 'results'.
	# The second parameter is the path where the stop words file is located.
	vocabulary = Vocabulary('results',stopwords='stopWords/stopwords.txt')

	# This function receive a folder path and try to append all documents of this folder into some structure. 
	vocabulary.import_folder('indexedFiles')

	# This function try to process all content of files that have been inserted before (using vocabulary.import_folder), 
	# generating the vocabulary data structure ready for use.
	vocabulary.index_files()

	# Persist data structure on disc.
	vocabulary.save()

	# This is a function that recover the vocabulary previously generated.
	vocabulary.import_collection()

	# Importing the Query module to process queries.
	from matchup.structure.query import Query

	# The Query is responsible for processing and generating user input to search a previously built create_collection
	# The parameter 'vocabulary' indicates which set of documents will be used.
	query = Query(vocabulary=vocabulary)

	query.ask(answer="agent data algorithm parallel information")

	#===================================
	#        Boolean IR model
	#===================================
	# Importing the Boolean model.
	from matchup.models.algorithms import Boolean

	# Receive an IR model and execute the query based in user answer and the vocabulary.
	# Selecting the Boolean model
	results = query.search(model=Boolean())	

	# Printing the results.
	print(results)

if __name__=="__main__":
	main()
