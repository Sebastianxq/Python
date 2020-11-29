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


	"""new new attempt with other stack ovverflow"""
	#plt.plot(dpkts, np.linspace(0,1,len(dpkts), endpoint=False))
	#plt.show()

	#ccdf is 1-cdf
	plt.plot(dpkts, 1-np.linspace(0,1,len(dpkts), endpoint=False))
	#plt.xscale('log')
	#plt.yscale('log')
	plt.show()

	"""new attempt with bins"""
	#counts, binEdges = np.histogram(dpkts, bins=20)
	#cdf = np.cumsum(counts)

	#plt.plot(binEdges[1:],cdf)
	#plt.xscale('log')
	#plt.yscale('log')
	#plt.show()

	"""New attempt without bins"""
	#yvals = np.arange(len(dpkts))/float(len(dpkts)-1)
	#plt.plot(dpkts, yvals)
	#plt.xscale('log')
	#plt.yscale('log')