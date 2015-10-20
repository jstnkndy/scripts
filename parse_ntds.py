#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:		parse_ntds.py
Purpose:	Takes the output of dsusers.py, output of hashcat, and prints
			the usernames, hashes, and cracked passwords together
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

import sys,re,argparse

def main():
	parser = argparse.ArgumentParser()
	
	parser.add_argument("--ntds", help="Output file from dsusers.py")
	parser.add_argument("--cracked", help="Output file from cracking")
	
	args = parser.parse_args()

	if (len(sys.argv) != 5):
		parser.print_help()
		sys.exit(1)

	users = {}
	pw_hashes = {}

	with file(args.ntds) as ntds_file:
		for line in ntds_file:
			if ':::' in line:
				line = ''.join(line.split())
				username = re.split(":", line)[0]
				pw_hash = re.findall(r"([a-z0-9]{32})", line)[0]
				users[username] = pw_hash

	with file(args.cracked) as cracked_file:
		for line in cracked_file:
			line = ''.join(line.split())
			pw_hash = re.split(":", line)[0]
			password = re.split(":", line)[1:][0]
			pw_hashes[pw_hash] = password

	for pw_hash in users:
		if users[pw_hash] in pw_hashes:
			print "{}, {}, {}".format(pw_hash, users[pw_hash], pw_hashes[users[pw_hash]])

if __name__ == '__main__':
	main()