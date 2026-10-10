from scapy.all import *
import time

print("=== NIDS Final Test ===")

print("1. Sending TCP SYN Scan...")

send(IP(dst="127.0.0.1")/TCP(dport=[i for i in range(1, 36)], flags="S"), verbose=0)
time.sleep(1)

print("2. Sending ARP Spoofing Attack...")

sendp(Ether()/ARP(op=2, psrc='10.0.2.15', hwsrc='aa:bb:cc:dd:ee:ff'), iface='lo', verbose=0)
sendp(Ether()/ARP(op=2, psrc='10.0.2.15', hwsrc='11:22:33:44:55:66'), iface='lo', verbose=0)
time.sleep(1)

print("3. Sending Spoofed ICMP Flood...")

sendp(Ether()/IP(src='192.168.99.99', dst='127.0.0.1')/ICMP(), iface='lo', count=55, verbose=0)
time.sleep(1)

print("4. Sending DNS Exfiltration Query...")

send(IP(dst="127.0.0.1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="a"*63 + ".com")), verbose=0)

print("=== All attacks launched ===")
