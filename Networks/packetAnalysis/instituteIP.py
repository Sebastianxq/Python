#!/usr/bin/python3
import sys, csv 

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')

	
	totalData = 0
	totalPkts = 0
	incomingTraffic = {}
	outgoingTraffic = {}
	incomingPackets = {}
	outgoingPackets = {}
	next(csvPacketCap) 
	for lines in csvPacketCap:
		totalData += int(lines[5])
		totalPkts += int(lines[4])
		
		#traffic coming from 128.112.0.0/16 block
		if lines[10] in incomingTraffic.keys():
			incomingTraffic[lines[10]] += int(lines[5])
			incomingPackets[lines[10]] += int(lines[4])
		elif lines[10].startswith("128.112"):
			incomingTraffic[lines[10]] = int(lines[5])
			incomingPackets[lines[10]] = int(lines[4])


		#traffic GOING to 128.112.0.0/16 block
		if lines[11] in outgoingTraffic.keys():
			outgoingTraffic[lines[11]] += int(lines[5])
			outgoingPackets[lines[11]] += int(lines[4])
		elif lines[11].startswith("128.112"):
			outgoingTraffic[lines[11]] = int(lines[5])
			outgoingPackets[lines[11]] = int(lines[4])


	#So I actually just need to match the netmask in my check
	#first 16 bytes is just 128.112
	#Would I have to check for the netmask too on this?? 
	
	#Sorts IPs and dumps into list
	sortedSrc = dict(sorted(incomingTraffic.items(), key=lambda item: item[1]))
	listIPs = list(sortedSrc.items())

	sortedOut = dict(sorted(outgoingTraffic.items(), key=lambda item: item[1]))
	listOut = list(sortedOut.items())

	#Packet stuff
	inPkts = dict(sorted(incomingPackets.items(), key=lambda item: item[1]))
	listInPkts = list(inPkts.items())
	sortedOutPkts = dict(sorted(outgoingPackets.items(), key=lambda item: item[1]))
	listOutPkts = list(sortedOutPkts.items())

	#Byte stuff
	totalIn, totalOut = 0,0
	for x in listIPs:
		totalIn += x[1]
	for x in listOut:
		totalOut += x[1]

	#Packet stuff again
	totalPktsIn, totalPktsOut = 0,0
	for x in listInPkts:
		totalPktsIn += x[1]
	for x in listOutPkts:
		totalPktsOut += x[1]
	
	print("Total Percent of bytes going in:%f" % (totalIn/totalData))
	print("Total percent of bytes going out:%f\n" % (totalOut/totalData))
	print("Total Percent of packets going in:%f" % (totalPktsIn/totalPkts))
	print("Total percent of packets going out:%f\n" % (totalPktsOut/totalPkts))


	
