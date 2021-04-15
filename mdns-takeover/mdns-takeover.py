from zeroconf import ServiceBrowser, Zeroconf

#Basic listener concepts stolen from Rob Guderian's Zeroconf service discoverer example.

class MalListener:
    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))
    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Service %s added, service info: %s" % (name, info))
        print(socket.inet_ntoa(info.addresses[0]))
    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Service %s updated, service info: %s" % (name, info))

zc = Zeroconf()
ml = MalListener()
browser = ServiceBrowser(zc, sys.argv[1], ml)

try:
    input("Press enter to exit...\n\n")
finally:
    zc.close()
