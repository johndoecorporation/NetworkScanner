from netaddr import valid_ipv4
import netifaces

class Arp :
    def __init__(self):        
        self.target = None
        self.gateway = None

    def regexIP(self,ip):
        if valid_ipv4(str(ip)):
            return True
        return False

    def askTarget(self):
        self.target = input('[*] Enter your victim ip address: ')
        print(netifaces.gateways())
        


a = Arp()
a.askTarget()




