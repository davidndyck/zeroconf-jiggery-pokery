# MDNS Amp

Attempts an MDNS Amplification attack against the given IP. Generally less than useful for a multitude of reasons.

Usage: sudo python3 mdns-amp.py <interface> <target> <service>

Where service is a service known to have lots of instances in mDNS.
Requires: SCAPY
Must be run as root
