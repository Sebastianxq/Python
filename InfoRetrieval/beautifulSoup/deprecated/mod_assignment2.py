import requests
from bs4 import BeautifulSoup
import pandas as pd
import os
import time
#get webpage and create bs object
req = requests.get('https://www.utep.edu/cs/people/index.html')
soup = BeautifulSoup(req.text,'lxml')

from re import search

#store all "div" tags in a list
divs = soup.findAll("div", {"class":"col-md-6"})

names, titles, room, email, phone, website = [],[],[],[],[],[]

#iterate through tags
for div in divs:

  #get professor titles
  facultyTitle = div.find("span",{"class":"Title"})
  if facultyTitle is not None:
    if "Professor" in facultyTitle.text:
      print(facultyTitle.text) #DEBUG
      titles.append(facultyTitle.text)

      facultyName = div.find("h3",{"class":"name"})
      if facultyName is not None:
        print(facultyName.text) #DEBUG
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
print(professors)

professors.to_pickle("professors.pkl") #push df to pkl file


term = input("Enter a search term:")
#term = "system" #DEBUG Term


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

#Prints out ranking and attributes from the df
#print(wordCount)
count = 0
for x in wordCount:
  count += 1
  fullEmail = x[1][:-4]+"@utep.edu"
  #print(fullEmail)

  #Once again, the trialing space forced a workaround
  if search("longpre",fullEmail):
    prof = professors[professors['Email'] == "longpre@utep.edu "]
  else:
    prof = professors[professors['Email'] == fullEmail]
  #print(prof)
  for index, row in prof.iterrows():
    #print(x[1]) #DEBUG
    #print(x[0])

    print("Rank #%d: The search term '%s' appear(s) %d times" % (count,term,x[0]) )
    print(row['Name'], row['Title']+'')
    print(row['Office'], row['Email'], row['Phone']+'')
    print("Website: %s\n"% (row['Website']))



##################################
"""
TODO 
3.)Restructure bs scrapper to be more ordered
4.)Modularize into classes
7.)It would be cool if the final query got 
  pulled into a text file titled 
  X_Query_Results.txt
"""
##################################