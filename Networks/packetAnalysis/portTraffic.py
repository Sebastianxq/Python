#!/usr/bin/python3
import sys, csv 
import matplotlib.pyplot as plt

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')

	#data=5,src=15, dst=16
	#dictName[src] += bytes
	totalData = 0
	srcDict, dstDict = {},{}
	next(csvPacketCap) #Ignores first line of csv (col name)
	for lines in csvPacketCap:
		totalData += int(lines[5])
		#print(lines[15])
		#print(lines[5])
		if lines[15] in srcDict.keys():
			#print("dict value curr:%d" % srcDict[lines[15]])
			newValue = srcDict[lines[15]]+int(lines[5])
			#print(newValue)
			srcDict[lines[15]] = newValue
			#print(srcDict)
		else:
			#print("adding new port")
			srcDict[lines[15]] = int(lines[5])

		if lines[16] in dstDict.keys():
			dstDict[lines[16]] += int(lines[5])
		else:
			dstDict[lines[16]] = int(lines[5])

	#print(totalData)
	
	sortedSrc = dict(sorted(srcDict.items(), key=lambda item: item[1]))
	top10Src = list(sortedSrc.items())
	top10Src = top10Src[-10:]
	#print("Top 10 SOURCE ports: %s\n" % (top10Src))

	sortedDst = dict(sorted(dstDict.items(), key=lambda item: item[1]))
	top10Dst = list(sortedDst.items())
	top10Dst = top10Dst[-10:]
	#print("Top 10 DESTINATION ports: %s\n" % (top10Dst))
	

	print("Top 10 SOURCE Ports")
	for port in top10Src:
		#print(float(port[1]))
		percentage = float(port[1])/float(totalData)
		print("port: %s,\t total: %d bytes,\t percentage: %f" % (port[0], port[1], percentage))

	print("\nTop 10 DESTINATION Ports")
	for port in top10Dst:
		#print(float(port[1]))
		percentage = float(port[1])/float(totalData)
		print("port: %s,\t total: %d bytes,\t percentage: %f" % (port[0], port[1], percentage))
	

