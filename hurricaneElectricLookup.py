#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:		hurricaneElectricLookup.py
Purpose:	Look up target network ranges using bgp.he.net
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

from bs4 import BeautifulSoup
import requests
import sys

def usage():
	print "Usage: %s <search string>" % sys.argv[0]


def main():
	if len(sys.argv) != 2:
		usage()
		sys.exit()

	search = sys.argv[1]

	headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.117 Safari/537.36"}
	url = "http://bgp.he.net/search?search%5Bsearch%5D=" + search + "&commit=Search"
	browser = requests.get(url, headers=headers)

	soup = BeautifulSoup(browser.text)
	table = soup.find("table")
	rows = table.findAll("tr")

	for row in rows:
		tds = row.findAll("td")
		try:
			a = str(tds[0].get_text())
			b = str(tds[1].get_text())
			print "%s, %s" % (a,b)
		except:
			continue

if __name__ == "__main__":
	main()