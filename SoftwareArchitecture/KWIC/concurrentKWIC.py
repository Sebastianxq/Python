#!/usr/bin/env python3

import threading      #For Semaphores, locks and threads
import Q              #Queue implementation

#Multithreading stuff
emptySem = threading.Semaphore(10) #empty queue
fullSem = threading.Semaphore(0) #full queue
lock = threading.Lock() #mutex
emptySem2 = threading.Semaphore(10) #empty queue
fullSem2 = threading.Semaphore(0) #full queue
lock2 = threading.Lock() #mutex

#pulls lines from file and puts them in a queue
def extractLines(filehandle, extractionQueue):
    while True:
        line = filehandle.readline()
        if not line:
          break

        emptySem.acquire()
        lock.acquire()
        if line is not None:
          wordArr = line.split()
          extractionQueue.put(wordArr)
        lock.release()
        fullSem.release()
    

    terminator = "..."
    emptySem.acquire()
    lock.acquire()
    extractionQueue.put(terminator)
    lock.release()
    fullSem.release()


#Generates the premutations from the words in the extraction queue
#stores then in final queue.
def permutate(extractionQueue, finalQueue):

     
     while True:     
       fullSem.acquire()
       lock.acquire()
       fileLine = extractionQueue.get()
       lock.release()
       emptySem.release()

       terminator = "..."  
       if(fileLine==terminator):
        emptySem2.acquire()
        lock2.acquire()
        finalQueue.put(terminator)
        lock2.release()
        fullSem2.release()
        break
       
       premutationList = []
       #generate premutations
       for i in range(len(fileLine)): 
       #generates all cyclic possibilies
         combined = fileLine[i:]+fileLine[:i]
         premutationList.append(combined)
       emptySem2.acquire()
       lock2.acquire()
       if premutationList is not None:
        finalQueue.put(premutationList)
       lock2.release()
       fullSem2.release()       

#reads lines from final queue
def sortLines(finalQueue):
    premutationList = []
    terminator = "..."
    while True:
      finalSet = finalQueue.get()
      if(finalSet==terminator):
        break
      if finalSet is not None:
        premutationList += finalSet  
    # Sorting list in case-insensitive manner
    finalSort = sorted(premutationList, key = lambda s: s[0][0][0].casefold()) 
    tempString = ""

    #Converts list into a string sentence
    for i in finalSort:
      for word in i:
        tempString+=word + " "
      print(tempString)
      tempString=""
         
           
     



#initialize queues
extractionQueue = Q.Queue() #Extract Queue
finalQueue = Q.Queue()    #Display Queue

try:
  fileName = input("What is the name of your file? ") 
  filehandle = open(fileName,"r")
except:
  print("Invalid Filename")
  exit()


#Creates threads for each method with the necessary args
extractL = threading.Thread(target = extractLines, args=(filehandle,extractionQueue))
permutateL = threading.Thread(target = permutate, args=(extractionQueue,finalQueue)) 

#Start threads
extractL.start()
permutateL.start()

#Waits for threads to finish so final list can be sorted.
extractL.join()
permutateL.join()
sortLines(finalQueue)
