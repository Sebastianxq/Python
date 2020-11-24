#!/usr/bin/python3
import sys, csv 
import matplotlib.pyplot as plt

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')

	
	totalData = 0
	srcIPs, srcMask = {},{}
	next(csvPacketCap) #Ignores first line of csv (col name)
	for lines in csvPacketCap:
		totalData += int(lines[5])
		
		#if lines[10] in srcIPs.keys(): #ORIGINAL
		if lines[10] in srcIPs.keys():
			#print("dict value curr:%d" % srcDict[lines[15]])
			srcIPs[lines[10]] += int(lines[5])
		elif lines[10] not in srcIPs.keys() and lines[20] == "0":
		#else: #ORIGINAL
			srcIPs[lines[10]] = int(lines[5])

		if lines[20] in srcMask.keys():
			srcMask[lines[20]] += int(lines[5])
		else:
			srcMask[lines[20]] = int(lines[5])

	#print(totalData) #DEBUG
	
	#Sorts IPs and dumps into list
	sortedSrc = dict(sorted(srcIPs.items(), key=lambda item: item[1]))
	listIPs = list(sortedSrc.items())


	#Get num of IPs in 0.1%, 1% and 10%
	numSrcIPs = len(listIPs)
	topPoint1 = int(numSrcIPs/1000)
	topOne = int(numSrcIPs/100)
	topTen = int(numSrcIPs/10)
	#print(type(topPoint1)) #DEBUG


	print("total num src IPs:%d" % numSrcIPs)
	print("0.1 contains: %d IPs" % topPoint1)
	print("1 contains: %d IPs" % topOne)
	print("10 contains: %d IPs\n" % topTen)
	
	#Creates a list containing only top X ips
	topPoint1List = listIPs[-topPoint1:]
	topOneList = listIPs[-topOne:]
	topTenList = listIPs[-topTen:]

	topPoint1Bytes, topOneBytes,topTenBytes = 0,0,0

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
