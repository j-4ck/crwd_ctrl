from scapy.all import *
import socket
import requests
import json

def revDNS(ip):
	try:
		return socket.gethostbyaddr(ip)[0]
	except socket.herror:
		return 'unknown'

def getVendor(mac):
	try:
		r = requests.get('http://macvendors.co/api/'+mac)
		data = r.content.replace("'","\"")
		dict = json.loads(data)
		return dict['result']['company']
	except:
		return 'unknown'

def main():
	conf.iface = 'wlan0'
	conf.verb = 0
	addrs = {}
	print '+' + '-'*86 + '+'
	print '| {0:13} | {1:13} | {2:17} | {3:32} |'.format('  HOSTNAME', ' '*5 +'IP', ' '*7 +'MAC', ' '*12 +'VENDOR')
	print '+' + '-'*86 + '+'
	for i in range(3):
		ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst='192.168.1.0/24'), timeout=1)
		for s,r in ans:
			if r.psrc not in addrs.keys():
				addrs[r.psrc] = r.src
				print '| {0:13} | {1:13} | {2:13} | {3:32} |'.format(revDNS(r.psrc), r.psrc, r.src, getVendor(r.src))
	print '+' + '-'*86 + '+'
	print addrs

if __name__ == '__main__':
	main()
