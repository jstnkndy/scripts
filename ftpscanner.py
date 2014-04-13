#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:		ftpscanner.py
Purpose:	Threaded anonymous ftp scanner
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

import Queue
import threading
import iptools
import sys
from ftplib import FTP

# Constant Variables
MAX_THREADS = 100
TIMEOUT = 2

class ThreadFTP(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.queue = queue
	def run(self):
		while True:
			host = self.queue.get()
			try:
				ftp = FTP(host, timeout=TIMEOUT)
				if ftp:
					if ftp.login("anonymous", "jsmith@aol.com"):
						ls = ftp.nlst()
						print "Success: %s %s" % (host, ls)
			except:
				pass
			self.queue.task_done()

def usage():
	print 'Usage: python %s <range>' % sys.argv[0]

def main():	
	if len(sys.argv) != 2:
		usage()
		sys.exit()
	
	ip_range = iptools.IpRangeList(sys.argv[1])
	queue = Queue.Queue()

	for host in ip_range:
		queue.put(host)
	for thr in range(MAX_THREADS):
		t = ThreadFTP(queue)
		t.setDaemon(True)
		t.start()
	queue.join()

if __name__ == '__main__':
	main()
