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
  rankingIndex = 0 
  for x in wordCount:
    rankingIndex += 1
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

if __name__ == '__main__':
  professors = webScrapper() #Scrapes Utep webpage and returns a dataframe with prof info
  

  #Assignment 2's ranking engine, likely wont be needed (read: REMOVED) on final submission
  #term = "test" #input("Enter a search term: ") 
  #wordCount = searchEngine(term) #Obtains a list of results from faculty websites
  #Prints out ranking and attributes from the df
  #rankingEngine(wordCount)

  # List of URLs. Insert the URLs of all faculty's web pages.
  #listWebpages = ['http://www.cs.utep.edu/isalamah/','http://www.cs.utep.edu/kiekintveld/','http://www.cs.utep.edu/makbar/']

  # Indexing faculty webpages
  #indexingWebpages(listWebpages)


  #===================================
  #           PREPROCESSING
  #===================================

  # Creating the data structure that represents and store all text processing
  # The first parameter is the 'path' where results are stored. In this case, the results will be stored in the folder 'results'.
  # The second parameter is the path where the stop words file is located.
  vocabulary = Vocabulary('results',stopwords='stopWords/stopwords.txt')

  # This function receive a folder path and try to append all documents of this folder into some structure. 
  vocabulary.import_folder('professors')

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


  #Models below might need weighting params!!!
  #===================================
  #        Vector Space IR model
  #===================================
  from matchup.models.algorithms import Vector
  #print(Vector)

  results = query.search(model=Vector())

  # Printing the results.
  print(results)


  #===================================
  #        Probabilistic IR model
  #===================================  
  from matchup.models.algorithms import Probabilistic
  #print(Probabilistic)
  #print(Boolean)
  results = query.search(model=Probabilistic())

  # Printing the results.
  print(results)