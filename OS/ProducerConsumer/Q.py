import threading

emptySem = threading.Semaphore(10) #stops from insetions to an full queue
fullSem = threading.Semaphore(0) #stops from insertions in a empty queue
lock = threading.Lock() #mutual exclusion when putting/getting queue

class Queue:
  #initializes the queue
  def __init__(self):
      self.queue = list()

  #stores the element into the front of the list
  def put(self,dataval):
      self.queue.insert(0,dataval)
     
  #Retrieve element if queue is not empty
  def get(self):
      if len(self.queue)>0:
          return self.queue.pop()
