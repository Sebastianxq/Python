#!/usr/bin/python3
import sys, getopt, argparse

from scapy.all import *
def print_pkt(pkt):
	pkt.show()


def parse_args():
    parser = argparse.ArgumentParser(description='Filter Packets based on type (ICMP) or source (IP/Port)')
    parser.add_argument('function', metavar='<function>', type=str,
                        help='select ICMP filter (1) or specific host/port (2)')
    parser.add_argument('--IP', metavar='<address>', type=str,
                        help='Select a IPv4 address')
    parser.add_argument('--port', metavar='<port>', type=str,
                        help='Select a port number')
    return parser.parse_args()

if __name__ == '__main__':
	args = parse_args()
	#Fix this in the future to be argument based. so 
	#./pScript <option>
	#./pScript <option> <ip> <port>
	#1 = icmp, 2 = ip and port
	#pkt = sniff(filter="icmp", prn=print_pkt)
	if args.function == '1':
		pkt = sniff(filter="icmp", prn=print_pkt)
	elif args.function == '2':
		IPfilter = "tcp and host "+args.IP+" and dst port "+args.port
		#print(IPfilter) #DEBUG
		pkt = sniff(filter=IPfilter, prn=print_pkt)
	else:
		sys.stderr.write("Please format your arguments in the following formats\n ICMP Filter: ./packetFilter.py 1\n IP/Port Filter: ./packetFilter.py 2 IPv4Addr portNum")
		sys.stderr.flush()