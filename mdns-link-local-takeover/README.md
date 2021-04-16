# mDNS Link-Local Takeover

Take over a zeroconf service by stealing a victim's IP and copying their mDNS advertisment. Also stops the victim from acquiring a different link-local IP

Usage: sudo python3 ./mdns-link-local-takeover.py <zone> <interface>
e.g.: sudo python3 ./mdns-link-local-takeover.py _test._tcp.local. enp0s8

Requires SCAPY
Must be run as root
