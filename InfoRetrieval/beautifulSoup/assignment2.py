import requests
from bs4 import BeautifulSoup
import pandas as pd
import os
import time
#get webpage and create bs object
req = requests.get('https://www.utep.edu/cs/people/index.html')
soup = BeautifulSoup(req.text,'lxml')

#store all "div" tags in a list
divs = soup.findAll("div", {"class":"col-md-6"})

names = []
titles = []
room = []
email = []
phone = []
website = []
#iterate through tags
for div in divs:

  #get professor titles
  facultyTitle = div.find("span",{"class":"Title"})
  if facultyTitle is not None:
    if "Professor" in facultyTitle.text:
      #print(facultyTitle.text)
      titles.append(facultyTitle.text)
    else:
      titles.append("N/A")

 #get professor names
    facultyName = div.find("h3",{"class":"name"})
    if facultyName is not None:
      #print(facultyName.text)
      names.append(facultyName.text)

    facultyRoom = div.find("span", {"class":"address"})
    if facultyRoom is not None:
      #print(facultyRoom.text)
      room.append(facultyRoom.text)

   #get professor emails
    facultyEmail = div.find("span", {"class": "email"})
    if facultyEmail is not None:
      #print(facultyEmail.text)
      email.append(facultyEmail.text)
      filename = facultyEmail.text[:-9] #@utep.edu, 9 numbers
      #print(facultyEmail.text)
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
    #print(len(facultyWebPage))
    facultyURL = facultyWebPage[len(facultyWebPage)-1].get("href")

   #if professor has webpage, store it in a text file
    if len(facultyURL) > 0:
      webPageContent = requests.get(facultyURL)
      #print(facultyURL)
      website.append(facultyURL)
      content = BeautifulSoup(webPageContent.text, "lxml")
      path2 = "professors/"+filename
      file = open(path2+".txt", "wt")
      n = file.write(content.text)
      file.close()
    else:
      website.append("N/A")
    #print("=========================")


d = {'Name': names, 'Title': titles, 'Office': room, 'Email': email,'Phone': phone, 'Website': website}
professors = pd.DataFrame(data = d)
print(professors)

professors.to_pickle("professors.pkl")


term = input("Enter a search term:")

#Search for the term within the text files in professor/
#Ranking Function
  #USes number of times the team appear in each text file

#file = fileLoc
#fileContents = file.read()
#numTimes =  fileContents.count(term)
#print("Number of times %s appeared is %d",term, numTimes)


#Get names of all the files in the directory
dirName = "professors/" 
directory = os.fsencode(dirName)
files = []
for file in os.listdir(directory):
 files.append(file.decode())

#Iterates throught files and counts the term

wordCount = [] #append a tuple of wordCount, fileName
start = time.time()
for file in files:
  filePtr = open(dirName+file)
  fileContents = filePtr.read()
  #print(fileContents) #Debug
  numTimes =  fileContents.count(term)
  if numTimes>0:
    wordCount.append( (numTimes,file) )

#sort (rank) listings
wordCount.sort(key = lambda x: x[0], reverse = True)

print("%d Results found in %s seconds" % (len(wordCount), time.time()-start))
for x in wordCount:
  print(x)

#print("Number of times", term, " appeared is:",numTimes)
#print("Search Time:%s seconds" % (time.time()-start))
  

  #Now need to rank, exclude anytime numTimes=0

#need to rank, so order some sort of tuple by num occurance
  #exclude those with 0
#from there, filter from dataframe and output the relevant stuff 


