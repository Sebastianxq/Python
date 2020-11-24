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
			srcIPs[lines[15]] += int(lines[5])
			#print(srcDict)
		else:
			#print("adding new port")
			srcIPs[lines[15]] = int(lines[5])

		if lines[20] in srcMask.keys():
			srcMask[lines[20]] += int(lines[5])
		else:
			srcMask[lines[20]] = int(lines[5])

	#print(totalData)
	
	sortedSrc = dict(sorted(srcIPs.items(), key=lambda item: item[1]))
	top10Src = list(sortedSrc.items())
	top10Src = top10Src[-10:]

	numSrcIPs = len(sortedSrc)
	print("total num src IPs:%d" % numSrcIPs)
	print("0.1 is: %d IPs" % (numSrcIPs/1000))
	print("1 is: %d IPs" % (numSrcIPs/100))
	print("10 is: %d IPs" % (numSrcIPs/10))
