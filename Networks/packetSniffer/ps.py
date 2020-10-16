#!/usr/bin/python3
from scapy.all import *

def printPkt(pkt):
	pkt.show()

pkt = sniff(filter="icmp", prn=printPkt)