from collections import defaultdict
import os
import sys
from scapy.all import *

#Dictionary to count how many SYN packets each IP sends
syn_tracker = defaultdict(int)
syn_threshold = 30

arp_table = {} #arp table to map every ip to mac address

icmp_tracker = defaultdict(int)
icmp_threshold = 50
dns_length_threshold = 52

def detect_syn_scan(packet):
#new function that inspects packets for TCP SYN port-scanning behavior

#Check if the packet has both an IP layer and a TCP layer (ignoring other packet types)
	if packet.haslayer(IP) and packet.haslayer(TCP):
		ip_src = packet[IP].src #takes source ip address from packet and put into variable
		tcp_flags = packet[TCP].flags #takes tcp header flag and '' '' 
# S represents SYN
		if tcp_flags == "S": #if the tcp header flag has a SYN flag, we add +1 to the syn tracker
			syn_tracker[ip_src] += 1
#if a singple IP sends or exceeds 30 packets, flag an alert
			if syn_tracker[ip_src] >= syn_threshold:
				print(
					f"SYN ALERT: Potential SYN Scan detected from {ip_src}!\nSuspicious activity possible due to {syn_tracker[ip_src]} SYN packets observed."
				)

def detect_arp_spoof(packet):
#new function that inspects packets for potential ARP spoofing 
	if packet.haslayer(ARP):
		if packet[ARP].op == 2 :
		#arp packet operations: 1 is request, 2 is reply, attackers forge replies to spoof
			real_ip = packet[ARP].psrc #arp source ip address
			real_mac = packet[ARP].hwsrc #arp source mac address
			if real_ip in arp_table:
				if arp_table[real_ip] != real_mac:
					print(
						f"ARP ALERT: Potential ARP Spoofing detected for IP {real_ip}!\nPreviously mapped MAC: {arp_table[real_ip]}\nNew claiming MAC: {real_mac}"
					)
			else:
				arp_table[real_ip] = real_mac
def detect_icmp_flood(packet):
#inspects packets for ICMP ping floods or dos attacks
	if packet.haslayer(IP) and packet.haslayer(ICMP):
		if packet[ICMP].type == 8:
		#type == 8 is an ICMP echo request
			ip_src = packet[IP].src
			icmp_tracker[ip_src] += 1
			if icmp_tracker[ip_src] == icmp_threshold:
				print(
					f"ICMP ALERT: Potential ICMP Flood detected from {ip_src}\n{icmp_tracker[ip_src]} pings observed, threshold is {icmp_threshold} pings"
				)
			elif icmp_tracker[ip_src] > icmp_threshold and icmp_tracker[ip_src] % 50 == 0:
				print(
					f"ICMP UPDATE: Ongoing ICMP Flood from {ip_src}\nTotal pings reached: {icmp_tracker[ip_src]}"
				)
def detect_dns_tunneling(packet):
#inspects DNS queries for abnormally long domains and possible exfiltration
	if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNSQR):
		if packet[UDP].dport == 53:
		#port 53 is standard DNS port
			query = packet[DNSQR].qname.decode('utf-8', errors='ignore')

			if len(query) > dns_length_threshold:
				ip_src = packet[IP].src
				print(
					f"DNS ALERT: Potential DNS Tunneling/Exfiltration from {ip_src}!\nSuspicious Query: {query} of length {len(query)}"
				)


def packet_callback(packet):
	detect_syn_scan(packet)
	detect_arp_spoof(packet)
	detect_icmp_flood(packet)
	detect_dns_tunneling(packet)

def main():
	#Packet sniffing requires root access, quick IF function to check if user ID = 0
	if os.geteuid() != 0:
		print(
		"ERROR: This script requires root or admin access to sniff the network."
		)
		sys.exit(1)
	print("Starting NIDS (Network Intrusion Detection System)... Pres CTRL+C to stop!\nSystem detection contains:\nSYN Scan detection\nARP Spoofing detection\nICMP Ping Flood detection\nDNS Tunneling detection\n\n")

	#Basic sniff call using a dummy callback (for now)
	try:
		sniff(iface=["lo", "enp0s3"], prn=packet_callback, store=0)
	except KeyboardInterrupt:
		print("\nShutting down NIDS.")
		sys.exit(0)

if __name__ == "__main__":
	main()
