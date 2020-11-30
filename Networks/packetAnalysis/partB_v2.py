#!/usr/bin/python3
import sys, csv 
import matplotlib.pyplot as plt
import numpy as np

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')
	
	dpkts,doctets,totalTime = [],[],[]
	next(csvPacketCap) #Ignores first line of csv (col name)
	for lines in csvPacketCap:
		
		dpkts.append(int(lines[4]))
		doctets.append(int(lines[5]))

		currentTime = int(lines[7])-int(lines[6])
		#print(currentTime)
		totalTime.append(currentTime)
	
	dpkts.sort(); totalTime.sort(); doctets.sort()


	"""calculates and plots cdf"""
	#plt.plot(dpkts, np.linspace(0,1,len(dpkts), endpoint=False))
	#plt.show()

	#ccdf is 1-cdf
	plt.plot(doctets, 1-np.linspace(0,1,len(doctets), endpoint=False))
	#plt.xscale('log')
	#plt.yscale('log')
	plt.show()