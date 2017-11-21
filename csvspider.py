#!/usr/bin/python3

import urllib.request
import urllib.parse
import ssl
import sys

roots = []
suffix = "/CVS/Entries"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def parse_entries(entries, target):
	for line in entries:
		line = line.decode("utf-8").rstrip()

		if line.startswith('D/'):
			print("{}{}".format(target,line.split("/")[1]))
			roots.append("{}{}/".format(target,line.split("/")[1]))

		elif line.startswith('/'):
			print("{}{}".format(target, line.split("/")[1]))

def main():
	if (len(sys.argv) != 2):
		print("Usage: python3 {} <target>".format(sys.argv[0]))
		sys.exit(1)

	start = sys.argv[1]

	if not start.endswith("/"):
		start += "/"

	roots.append(start)

	while roots:
		target = roots.pop()

		if(target.startswith("https://")):
			try:
				r = urllib.request.urlopen("{}{}".format(target, suffix), context=ctx)
			except Exception as e:
				print("Exception: {} - {}".format(e, target))
				next
		elif(target.startswith("http://")):
			try:
				r = urllib.request.urlopen("{}{}".format(target, suffix))
			except Exception as e:
				print("Exception: {} - {}".format(e, target))
				next
		else:
			print("Target should start with http or https")
			sys.exit(1)

		data = r.readlines()
		parse_entries(data, target)


if __name__ == '__main__':
	main()
