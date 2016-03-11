#!/usr/bin/python

"""
-------------------------------------------------------------------------------
Name:		dns_listener.py
Purpose:	Listens for incoming DNS requests, prints if argv1 is in qname.
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

import sys
import argparse
import signal
from scapy.all import *


def pkt_callback(pkt, domain):
    if DNSQR in pkt:
        if domain in pkt[DNS].qd.qname:
            print pkt[DNS].qd.qname

def signal_handler(signal, frame):
    print "Caught signal, exiting!";
    sys.exit(signal)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--interface", help="Interface to sniff on")
    parser.add_argument("--domain", help="String to match on")

    if len(sys.argv) != 5:
        parser.print_help()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    args = parser.parse_args()

    interface = args.interface
    domain = args.domain
    filter = 'udp and port 53'

    sniff(iface=interface, filter=filter, prn=lambda x: pkt_callback(x, domain))

if __name__ == "__main__":
    main()