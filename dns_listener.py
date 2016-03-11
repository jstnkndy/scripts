#!/usr/bin/python

"""
-------------------------------------------------------------------------------
Name:		dns_listener.py
Purpose:	Listens for incoming DNS requests, prints if argv1 is in qname.
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

import sys
from scapy.all import *

def usage():
    print 'Usage: {} <domain>'.format(sys.argv[0])

def pkt_callback(pkt, domain):
    if DNSQR in pkt:
        if domain in pkt[DNS].qd.qname:
            print pkt[DNS].qd.qname


def main():
    if len(sys.argv) != 1:
        usage()
        sys.exit(1)

    interface = 'eth0'
    filter = 'udp and port 53'
    domain = sys.argv[1]

    sniff(iface=interface, filter=filter, prn=lambda x: pkt_callback(x, domain))

if __name__ == "__main__":
    main()