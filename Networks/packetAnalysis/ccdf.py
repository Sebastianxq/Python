#!/usr/bin/python3
import sys, csv 
import matplotlib.pyplot as plt

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')
	
	dpkts = []
	doctets = []
	totalTime = []
	next(csvPacketCap) #Ignores first line of csv (col name)
	for lines in csvPacketCap:
		
		dpkts.append(int(lines[4]))
		doctets.append(int(lines[5]))

		currentTime = int(lines[7])-int(lines[6])
		#print(currentTime)
		totalTime.append(currentTime)
	
	dpkts.sort(); totalTime.sort(); doctets.sort()

	#print(dpkts)
	#print(totalTime) #DEBUG
	plt.plot(totalTime, dpkts) #format is x,y
	#plt.ylabel('Total Packets')
	#plt.xlabel('totalTime')
	plt.show()