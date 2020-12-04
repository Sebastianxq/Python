#!/usr/bin/python3
import requests
from bs4 import BeautifulSoup
import pandas as pd
import os
import time
from re import search
from matchup.structure.vocabulary import Vocabulary
import html2text
from urllib.request import urlopen
from matchup.structure.query import Query #Process Queries
from matchup.models.algorithms import Boolean #Import Boolean Model
from matchup.models.algorithms import Vector #Import Vector Model
from matchup.models.algorithms import Probabilistic #Import Probabilistic Model

def webScrapper():
  names, titles, room, email, phone, website = [],[],[],[],[],[]

  #get webpage and create bs object
  req = requests.get('https://www.utep.edu/cs/people/index.html')
  soup = BeautifulSoup(req.text,'lxml')

  #store all "div" tags in a list
  divs = soup.findAll("div", {"class":"col-md-6"})


  #iterate through tags
  for div in divs:

    #get professor titles
    facultyTitle = div.find("span",{"class":"Title"})
    if facultyTitle is not None:
      if "Professor" in facultyTitle.text:
        #print(facultyTitle.text) #DEBUG
        titles.append(facultyTitle.text)

        facultyName = div.find("h3",{"class":"name"})
        if facultyName is not None:
          #print(facultyName.text) #DEBUG
          names.append(facultyName.text)


        facultyRoom = div.find("span", {"class":"address"})
        if facultyRoom is not None:
          #print(facultyRoom.text)
          room.append(facultyRoom.text)

        #get professor emails
        facultyEmail = div.find("span", {"class": "email"})
        if facultyEmail is not None:
          profEmail = facultyEmail.text
          #print(profEmail)
          email.append(profEmail)

          #due to a trailing space, longpre needs extra validation
          if "long" in facultyEmail.text:
            filename = "longpre"
          else:  
            filename = profEmail[:-9] # removes "@utep.edu"
        else:
          email.append("N/A")

        #get professor emails
        facultyPhone = div.find("span", {"class": "phone"})
        if facultyPhone is not None:
          #print(facultyPhone.text)
          phone.append(facultyPhone.text)
        else:
          phone.append("N/A")

        #get professors webpage (if applicable)
        facultyWebPage = div.findAll("a")
        facultyURL = facultyWebPage[len(facultyWebPage)-1].get("href")

        #if professor has webpage, store it in a text file
        if len(facultyURL) > 0:
          webPageContent = requests.get(facultyURL)
          #print(facultyURL)
          website.append(facultyURL)
          content = BeautifulSoup(webPageContent.text, "lxml")
          profFilePath = "professors/"+filename
          file = open(profFilePath+".txt", "wt")
          n = file.write(content.text)
          file.close()
        else:
          website.append("N/A")
        #print("=========================")

  #Creates format for the dataframe and then instantiates it
  d = {'Name': names, 'Title': titles, 'Office': room, 'Email': email,'Phone': phone, 'Website': website}
  professors = pd.DataFrame(data = d)
  professors.to_pickle("professors.pkl")
  return professors

def searchEngine(term):
  #Get names of all the files in the directory
  dirName = "professors/" 
  directory = os.fsencode(dirName)
  files = []
  for file in os.listdir(directory):
    files.append(file.decode())


  wordCount = [] #append a tuple of wordCount, fileName
  start = time.time() #calculates search time

  #Iterate through each file, if word appears in file, add to list
  for file in files:
    filePtr = open(dirName+file)
    fileContents = filePtr.read()
    #print(fileContents) #Debug
    numTimes =  fileContents.count(term)
    if numTimes>0:
      wordCount.append( (numTimes,file) )

  wordCount.sort(key = lambda x: x[0], reverse = True) #sort (rank) listings
  print("\n%d Results found in %s seconds" % (len(wordCount), time.time()-start))
  return wordCount

def rankingEngine(wordCount):
  #rankingIndex = 0 
  for x in wordCount:
    #rankingIndex += 1
    fullEmail = x[1][:-4]+"@utep.edu"
    #print(fullEmail)

    #Once again, the trialing space forced a workaround
    if search("longpre",fullEmail):
      prof = professors[professors['Email'] == "longpre@utep.edu "]
    else:
      prof = professors[professors['Email'] == fullEmail]
    for index, row in prof.iterrows():
      #print(x[1]) #DEBUG
      #print(x[0])

      print("Rank #%d: The search term '%s' appear(s) %d times" % (rankingIndex,term,x[0]) )
      print(row['Name'], row['Title']+'')
      print(row['Office'], row['Email'], row['Phone']+'')
      print("Website: %s\n"% (row['Website']))

def matchup(listing):
  """listing has 2 attributes: 
    listing.results which returns a list of results

    str_n(n) which returns the Nth ranking of the results"""
  resultList = listing.results
  rankingIndex = 0
  for item in resultList:
    #items in the list have the form [fileName, ranking]
    #print(item[0])
    #print(item[1])
    #professors/agates.txt needs to remove everything except "agates"
    rankingIndex+=1
    fullEmail = item[0][11:-4]+"@utep.edu"
    term="TEST"
    if search("longpre",fullEmail):
      prof = professors[professors['Email'] == "longpre@utep.edu "]
    else:
      prof = professors[professors['Email'] == fullEmail]
    for index, row in prof.iterrows():
      #print(x[1]) #DEBUG
      #print(x[0])

      print("Rank #%d: %s" % (rankingIndex,item[1]) )
      print(row['Name'], row['Title']+'')
      print(row['Office'], row['Email'], row['Phone']+'')
      print("Website: %s\n"% (row['Website']))

#Goes through query file and takes in ONLY the query content.
#Returns queries as a list
def getQueries():
  lines = []
  try:
      queryFile = open("query.txt", "r")
      for line in queryFile: 
        if search("Query",line):
          line = line[7:].rstrip() #Takes out "QUERY:" portion and the trailing newline
          lines.append(line)
      #print(lines) #DEBUG
  except IOError:
     print("Could not find Query File!")

  return lines
  
def performQueries(queryList):
  query = Query(vocabulary=vocabulary)
  count = 1
  for question in queryList:
    #Results for query 1 : agent data algorithm parallel information
    print("\033[1m \033[91m \033[4m Results for query %d: %s \033[0m" % (count,question))
    count+=1
    query.ask(answer=question)


    #===================================
    #        Boolean IR model
    #===================================
    start = time.time() #calculates search time
    results = query.search(model=Boolean()) 
    finalTime = time.time()-start
    print('\033[1m' + "Boolean Model" + '\033[0m')
    print("%s Results found (%f sec)\n" % (len(results.results),finalTime))
    matchup(results)

    #===================================
    #        Vector Space IR model
    #===================================
    start = time.time() #calculates search time
    vectorResults = query.search(model=Vector())
    finalTime = time.time()-start
    print('\n'+'\033[1m' + "Vector Space Model" + '\033[0m')
    print("%s Results found (%f sec)\n" % (len(vectorResults.results),finalTime))
    matchup(vectorResults)
    #===================================
    #        Probabilistic IR model
    #===================================  
    start = time.time() #calculates search time
    probResults = query.search(model=Probabilistic())
    finalTime = time.time()-start
    print('\n'+'\033[1m' + "Probabilistic Model" + '\033[0m')
    print("%s Results found (%f sec)\n" % (len(probResults.results),finalTime))
    matchup(probResults)

if __name__ == '__main__':
  professors = webScrapper() #Scrapes Utep webpage and returns a dataframe with prof info
  
  #===================================
  #           PREPROCESSING
  #===================================

  # Creating the data structure that represents and store all text processing
  # The first parameter is the 'path' where results are stored. In this case, the results will be stored in the folder 'results'.
  # The second parameter is the path where the stop words file is located.
  vocabulary = Vocabulary('results',stopwords='stopWords/stopwords.txt')
  vocabulary.import_folder('professors')
  vocabulary.index_files()
  vocabulary.save()
  vocabulary.import_collection()


  # The Query is responsible for processing and generating user input to search a previously built create_collection
  # The parameter 'vocabulary' indicates which set of documents will be used.

  queryList = getQueries()


  #Create some loop here that will go through ALL of the queries
  #for x in queryList:
  #  print(x)


  performQueries(queryList)
 