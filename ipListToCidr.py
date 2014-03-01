#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:		ipListToCidr.py
Purpose:	Condense an ip list to cidr ranges
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

import netaddr
import sys

def usage():
	print "Usage:", sys.argv[0], "<ip list>"

def main():
	if len(sys.argv) < 2:
		usage()
		sys.exit()
	
	ipFile = open(sys.argv[1])
	ipAddresses = [i for i in ipFile.readlines()]
	ipAddresses = sorted(ipAddresses)
	cidrs = netaddr.cidr_merge(ipAddresses)
	for cidr in cidrs:
		print cidr

if __name__ == '__main__': 
	main()

