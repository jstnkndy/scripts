#!/usr/bin/env ruby

=begin
-------------------------------------------------------------------------------
Name:		subDomainBruteforcer.rb
Purpose:	Script to quickly resolve subdomains to network addresses
Author:		Justin Kennedy (@jstnkndy)
------------------------------------------------------------------------------
=end

require 'resolv'

def resolve_dns(subdomain, wildcard_address)
	begin
		subdomain_addresses = Resolv.getaddresses(subdomain)
		subdomain_addresses.each do |subdomain_address|
			if subdomain_address != wildcard_address
				puts "#{subdomain_address} - #{subdomain}"
			end
		end
	rescue StandardError => error
	end
end

def check_for_wildcard(wildcard_domain)
	begin
		wildcard_address = Resolv.getaddress(wildcard_domain)
	rescue StandardError => error
	end
end

def usage
	puts "Usage: #{$0} <domain_wordlist> <subdomain_wordlist>"
	exit
end

domains_wordlist, subdomains_wordlist = ARGV
usage unless ARGV.length == 2

domains = []
subs = []

File.read(domains_wordlist).split("\n").each { |domain| domains << domain}
File.read(subdomains_wordlist).split("\n").each { |sub| subs << sub }

domains.each do |domain|
	wildcard_address = check_for_wildcard("thishouldneverexist.#{domain}")
	subs.each do |sub|
		subdomain = "#{sub}.#{domain}"
		resolve_dns(subdomain, wildcard_address)
	end
end
