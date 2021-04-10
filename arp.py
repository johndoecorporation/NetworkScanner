from scan import Network

class Arp :
    def __init__(self):        
        self.target = None
        self.gateway = Network().getGateway()

    def askTarget(self):
        self.target = input('[*] Enter your victim ip address: ')


a = Arp()
a.askTarget()




