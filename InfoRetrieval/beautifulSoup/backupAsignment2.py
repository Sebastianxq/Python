import requests
from bs4 import BeautifulSoup

#get webpage and create bs object
req = requests.get('https://www.utep.edu/cs/people/index.html')
soup = BeautifulSoup(req.text,'lxml')

#store all "div" tags in a list
divs = soup.findAll("div", {"class":"col-md-6"})

professors = pd.DataFrame()
professorInfo = []
#iterate through tags
for div in divs:

  #get professor titles
  facultyTitle = div.find("span",{"class":"Title"})
  if facultyTitle is not None:
    if "Professor" in facultyTitle.text:
      print(facultyTitle.text)
      dfTitle = facultyTitle.text

 #get professor names
  facultyName = div.find("h3",{"class":"name"})
  if facultyName is not None:
    print(facultyName.text)
    dfName = facultyName.text

  facultyRoom = div.find("span", {"class":"address"})
  if facultyRoom is not None:
    print(facultyRoom.text)
    dfRoom = facultyRoom.text

 #get professor emails
  facultyEmail = div.find("span", {"class": "email"})
  if facultyEmail is not None:
    print(facultyEmail.text)
    dfEmail = facultyEmail.text

  #get professor emails
  facultyPhone = div.find("span", {"class": "phone"})
  if facultyPhone is not None:
    print(facultyPhone.text)
    dfPhone = facultyPhone.text

 #get professors webpage (if applicable)
  facultyWebPage = div.findAll("a")
 #print(len(facultyWebPage))
  facultyURL = facultyWebPage[len(facultyWebPage)-1].get("href")

 #if professor has webpage, store it in a text file
  if len(facultyURL) > 0:
    webPageContent = requests.get(facultyURL)
    print(facultyURL)
    dfURL = facultyURL
    content = BeautifulSoup(webPageContent.text, "lxml")
        #file = open(facultyName.text+".txt", "wt")
        #n = file.write(content.text)
        #file.close()
  print("=========================")

  #professorInfo.append(facultyName,facultyTitle, facultyOffice, facultyEmail,facultyPhone,facultyURL)
