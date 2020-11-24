#!/usr/bin/python3
import sys, csv 
import matplotlib.pyplot as plt

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')
	
	#1.)What fraction of traffic came from 0.1% of source IP prefixes
	#Top 1%
	#Top 10
	#Source Mask length=0
	"""
	srcaddr is 10
	Mask length is 20
	totalTraffic is unchanged

	Once again do a dict but this time get srcaddr
	For one instance get mask length
	"""

	
	totalData = 0
	srcIPs, srcMask = {},{}
	next(csvPacketCap) #Ignores first line of csv (col name)
	for lines in csvPacketCap:
		totalData += int(lines[5])
		#print(lines[15])
		#print(lines[5])
		if lines[10] in srcIPs.keys():
			#print("dict value curr:%d" % srcDict[lines[15]])
			#print(newValue)
			srcIPs[lines[10]] += int(lines[5])
			#print(srcDict)
		else:
			#print("adding new port")
			srcIPs[lines[10]] = int(lines[5])

		if lines[20] in srcMask.keys():
			srcMask[lines[20]] += int(lines[5])
		else:
			srcMask[lines[20]] = int(lines[5])

	#print(totalData)
	
	#Sorts IPs and dumps into list
	sortedSrc = dict(sorted(srcIPs.items(), key=lambda item: item[1]))
	listIPs = list(sortedSrc.items())


	numSrcIPs = len(listIPs)
	topPoint1 = int(numSrcIPs/1000)
	#print(type(topPoint1)) #DEBUG
	topOne = int(numSrcIPs/100)
	topTen = int(numSrcIPs/10)

	print("total num src IPs:%d" % numSrcIPs)
	print("0.1 contains: %d IPs" % topPoint1)
	print("1 contains: %d IPs" % topOne)
	print("10 contains: %d IPs\n" % topTen)
	
	topPoint1List = listIPs[-topPoint1:]
	topOneList = listIPs[-topOne:]
	topTenList = listIPs[-topTen:]

	topPoint1Bytes = 0
	topOneBytes = 0
	topTenBytes = 0
	for ip in topPoint1List:
		topPoint1Bytes+=ip[1]
	print("Top 0.1 Percentage: %f" % (float(100*topPoint1Bytes/totalData)))

	for ip in topOneList:
		topOneBytes+=ip[1]
	print("Top 1 Percentage: %f" % (float(100*topOneBytes/totalData)))

	for ip in topTenList:
		topTenBytes+=ip[1]
	print("Top 10 Percentage: %f\n" % (float(100*topTenBytes/totalData)))



	#Sorts flows with no mask
	maskSorted = dict(sorted(srcMask.items(), key=lambda item: item[1]))
	listMask = list(maskSorted.items())
	maskBytes = 0
	for maskIP in listMask:
		if maskIP[0] == "0":
			maskBytes +=maskIP[1]
	#print(maskBytes) DEBUG
	print("Mask Traffic Percentage: %f" % (float(100*maskBytes/totalData)))

