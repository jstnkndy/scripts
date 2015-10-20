#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:		parse_wdigest.py
Purpose:	Takes the output of mimikatz's wdigest and outputs it cleaner
Author:		Justin Kennedy (@jstnkndy)
-------------------------------------------------------------------------------
"""

import sys, re


def usage():
    print 'Usage: python {} <input file>'.format(sys.argv[0])


def main():
    if len(sys.argv) != 2:
        usage()
        exit()

    username_regex = re.compile(r'\*\s+Username\s+:\s+(.*)')
    domain_regex = re.compile(r'\*\sDomain\s+:\s(.*)')
    password_regex = re.compile(r'\*\s+Password\s+:\s+(.*)')

    usernames, domains, passwords = [], [], []

    with open(sys.argv[1], 'r') as input:
        data = input.read()

        [usernames.append(username) for username in re.findall(username_regex, data)]
        [domains.append(domain) for domain in re.findall(domain_regex, data)]
        [passwords.append(password) for password in re.findall(password_regex, data)]

    for i in range(0, len(usernames)):
        print '{}\\{} - {}'.format(domains[i], usernames[i], passwords[i])


if __name__ == '__main__':
    main()
