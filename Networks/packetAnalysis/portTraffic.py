#!/usr/bin/python3
import sys, csv 
import matplotlib.pyplot as plt

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')
	
	#1.	Create two tables, listing the top-ten port numbers 
	#by sender traffic volume and by receiver traffic volume 
	#including the percentage of traffic (by bytes) 
	#they contribute. 

	"""
	So for the first table: get top 10 src ports
	based on traffic
	1.)make a dict of src_port:bytes
	2.)Sort and take top 10 list
	3.)Get total num of bytes too to get percentage

	For second: get top 10 dst ports by traffic


	For dicts: store all unique ports first

	"""	

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

		if lines[16] in dstDict:
			dstDict[lines[16]] += int(lines[5])
		else:
			dstDict[lines[16]] = int(lines[5])

	#print(totalData)
	
	sortedSrc = dict(sorted(srcDict.items(), key=lambda item: item[1]))
	top10Src = list(sortedSrc.items())
	print("Top 10 SOURCE ports: %s\n" % (top10Src[-10:]))

	sortedDst = dict(sorted(dstDict.items(), key=lambda item: item[1]))
	top10Dst = list(sortedDst.items())
	print("Top 10 DESTINATION ports: %s\n" % (top10Dst[-10:]))
	#for pair in srcDict.items():
	#	print(pair) #DEBUG


