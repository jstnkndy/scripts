#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:		rbackup.py
Purpose:	Remote cisco configuration backup
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

import sys
import datetime
import pexpect

def login(host, username, password):
	""" Prompt Types """
	newkey = 'yes/no'
	passprompt = 'password:'

	cisco = pexpect.spawn('ssh %s@%s' % (username, host))
	response = cisco.expect([newkey, passprompt, pexpect.EOF])

	if response == 0:
		cisco.sendline('yes')
		response = cisco.expect([newkey, passprompt, pexpect.EOF])
	if response == 1:
		cisco.sendline(password)
		cisco.expect('.*>')
		return cisco
	elif response == 2:
		print "Unable to login to:", host
		pass

def enlogin(child, enpass):
	child.sendline('enable')
	child.expect('Password: ')
	child.sendline(enpass)
	child.expect('.*')

def get_prompt(child):
	return ''.join(child.after).strip()

def get_enprompt(child):
	return ''.join(child.after).strip()

def backup_runconf(child, enprompt, log, hostname):
	child.sendline('terminal length 0')
	child.expect(enprompt)
	child.sendline('show run')
	child.expect(enprompt)

	fh = open(log, 'w')
	fh.write(child.before)
	fh.close

	print "[+] Backup Successful on:", hostname

def usage():
	print 'Usage: python %s <list>' % sys.argv[0]

def main():
	if len(sys.argv) != 2:
		usage()
		sys.exit()

	username = 'admin'
	password = ''
	enpass = ''
	hosts = open(sys.argv[1])
	
	for host in hosts:
		host = host.strip()
		cisco = login(host, username, password)

		if cisco:
			prompt = get_prompt(cisco)
			enlogin(cisco, enpass)
			enprompt = get_enprompt(cisco)
			hostname =  enprompt[:len(enprompt) - 1]
			log = str(hostname) + "-" + str(datetime.date.today())

			backup_runconf(cisco, enprompt, log, hostname)

if __name__ == '__main__':
	main()
