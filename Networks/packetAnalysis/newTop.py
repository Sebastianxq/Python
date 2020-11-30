#!/usr/bin/python3
import sys, csv 
import matplotlib.pyplot as plt

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')

	
	totalData = 0
	srcIPs, srcMask = {},{}
	srcIPCount = {}
	totalLines = 0
	next(csvPacketCap) #Ignores first line of csv (col name)
	for lines in csvPacketCap:
		totalLines += 1
		
		if lines[10] in srcIPs.keys() and lines[20] != "0":
			#print("dict value curr:%d" % srcDict[lines[15]])
			#print("more data from ip %s with a mask:%s" % (lines[10], lines[20]))
			srcIPs[lines[10]] += int(lines[5])
			totalData += int(lines[5])
		elif lines[10] not in srcIPs.keys() and lines[20] != "0":
			#print("addind ip %s with a mask:%s" % (lines[10], lines[20]))
			srcIPs[lines[10]] = int(lines[5])
			totalData += int(lines[5])


		#Counts total number of times an IP has appeared
		if lines[10] in srcIPCount.keys() and lines[20] != "0":
			srcIPCount[lines[10]] += 1
		elif lines[10] not in srcIPCount.keys() and lines[20] != "0":
			srcIPCount[lines[10]] = 1

		#Counts data from netmasked IPs
		if lines[20] in srcMask.keys():
			srcMask[lines[20]] += int(lines[5])
		else:
			srcMask[lines[20]] = int(lines[5])

	print(totalLines) #DEBUG
	
	#Sorts IPs and dumps into list
	sortedSrc = dict(sorted(srcIPs.items(), key=lambda item: item[1]))
	listIPs = list(sortedSrc.items())

	#Sorts IPs and dumps into list
	sortIPCount = dict(sorted(srcIPCount.items(), key=lambda item: item[1]))
	sortedNumOccurance = list(sortIPCount.items())


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

	#Creates a list containing only top X ips
	#print(sortedNumOccurance)
	count1 = sortedNumOccurance[-topPoint1:]
	count2= sortedNumOccurance[-topOne:]
	count3 = sortedNumOccurance[-topTen:]
	#print(count1)



	topPoint1Bytes, topOneBytes,topTenBytes = 0,0,0
	#print(totalBytes)
	for ip in count1:
		for x in listIPs:
			if ip[0] == x[0]:
				#print("countIP:%s and byteIP:%s" %(ip[0],x[0]))
				topPoint1Bytes+=x[1]
	print("Top Point 1 Percentage: %f, Total Bytes: %d" % (float(100*topPoint1Bytes/totalData), topPoint1Bytes))

	for ip in count2:
		for x in listIPs:
			if ip[0] == x[0]:
				topOneBytes+=x[1]
	print("Top 1 Percentage: %f, Total Bytes: %d" % (float(100*topOneBytes/totalData), topOneBytes))

	for ip in count3:
		for x in listIPs:
			if ip[0] == x[0]:
				topTenBytes+=x[1]
	print("Top 10 Percentage: %f, Total Bytes: %d" % (float(100*topTenBytes/totalData), topTenBytes))





	#Sorts flows with no mask
	# maskSorted = dict(sorted(srcMask.items(), key=lambda item: item[1]))
	# listMask = list(maskSorted.items())
	# maskBytes = 0
	# for maskIP in listMask:
	# 	if maskIP[0] == "0":
	# 		maskBytes +=maskIP[1]
	# print(maskBytes) #DEBUG
	# print("Mask Traffic Percentage: %f" % (float(100*maskBytes/totalData)))
