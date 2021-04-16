# Link Local Takeover

"Takes over" a link-local IP and prints packets sent to that IP. Victim must be RFC 3927 compliant (looking at you, Windows)

Usage: sudo python3 link-local-takeover.py <iface> <ip>

Requires SCAPY
Must be run as root
