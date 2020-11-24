#!/usr/bin/python3
import sys, csv


#Calculates avg size of packets in capture
def avgSize(packetCap):
	#NOTE: flow is the sequence of packets from src to dst
	totalPkts,totalBytes = 0,0


	next(packetCap) #Ignores first line of csv (col name)
	for lines in packetCap:
		#print(lines[5]) #DEBUG
		
		totalPkts +=  int(lines[4])
		totalBytes += int(lines[5])

	print("Avg bytes per packet:%d" % (totalBytes/totalPkts))

if __name__ == '__main__':
	packetCap = open("Netflow_dataset.csv", "r")
	csvPacketCap = csv.reader(packetCap, delimiter=',')
	

	avgSize(csvPacketCap)