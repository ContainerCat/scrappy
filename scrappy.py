import argparse
import textwrap
import sys
import json
from scapy.layers.l2 import Ether, ARP, srp
from scapy.layers.inet import IP, sr1, UDP, ICMP, TCP
from scapy.sendrecv import sr, sniff
from scapy.layers.http import HTTPRequest
from scapy.packet import Raw

class Scrappy:
    def __init__(self, args):
        self.args = args

    def run(self):
        target = self.args.target
        if not target:
            sys.exit("no target specified")
        
        if self.args.discoverhost:
            self.discoverHost(target)
        elif self.args.service:
            self.discoverService(target)
        elif self.args.os:
            self.discoverOS(target)
        elif self.args.pcap:
            self.pcap(target)

    def discoverHost(self, range):
        
        answer, unanswer= srp( Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=range), timeout=10)
        f = open(self.args.file, "a")
        f.write("#### All hosts in your network ####\n" )

        for sent, received in answer:
            tempjson = {'IP': received.psrc, 'MAC': received.hwsrc}

            f.write(json.dumps(tempjson)+"\n")
        
        f.write("########################################################################\n")
        f.close()


    def discoverService(self, ip):
        f = open(self.args.file, "a")
        f.write(f"#### All open ports for host:{ip} ####\n")

        for x in range(1,1025):
            res = sr1( IP(dst=ip) / UDP(sport=x, dport=x), timeout=2 )
            if res == None:
                f.write(f"Port: {x} open / filtered\n")

            else:
                if res.haslayer(ICMP):
                    next()
                elif res.haslayer(UDP):
                    f.write(f"Port: {x} open / filtered\n")
                else:
                    f.write(f"Port: {x} status unknown\n")

        
        f.write("########################################################################\n\n")
        f.close()
        

    def discoverOS(self, ip):
        res = sr1( IP(dst=ip) / ICMP(id=100), timeout=10)
        os = ""

        if res :
            if IP in res:
                ttl = res.getlayer(IP).ttl
                if ttl <= 64:
                    os = "Linux"
                elif ttl > 64:
                    os = "Windows"
                else:
                    os = None


        if os is None or os =="":
            sys.exit("no OS found")

        f = open(self.args.file, "a")
        f.write("#### OS detection ####\n")
        f.write(f"host: {ip} has os: {os}\n")
        f.write("########################################################################\n\n")
        f.close()


    def pcap(self, ip):
        f= open(self.args.file, "a")
        f.write("#### Sniff network for http traffic ####\n")
        sniff(prn=self.process_packet, timeout=20)


    def process_packet(self, packet):

        f = open(self.args.file, "a")
        if packet.haslayer(HTTPRequest):
            ipS = packet[IP].src
            ipD = packet[IP].dst
            ttl = packet[IP].ttl
            portS = packet[TCP].sport
            portD = packet[TCP].dport

            f.write(f"source: {ipS}:{portS}\tdestination: {ipD}:{portD}\t\ttime to life:{ttl}\n")
            f.write("########################################################################\n\n")
            f.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description= "A tool based on scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog= textwrap.dedent('''
            .'\   /`.
         .'.-.`-'.-.`.
    ..._:   .-. .-.   :_...
  .'    '-.(o ) (o ).-'    `.     -- lets get scrappy
 :  _    _ _`~(_)~`_ _    _  :
:  /:   ' .-=_   _=-. `   ;\  :
:   :|-.._  '     `  _..-|:   :
 :   `:| |`:-:-.-:-:'| |:'   :
  `.   `.| | | | | | |.'   .'
    `.   `-:_| | |_:-'   .'
      `-._   ````    _.-'
          ``-------''

        '''))
    parser.add_argument("-d", "--discoverhost", action= "store_true", help="search network for alive hosts")
    parser.add_argument("-s", "--service", action= "store_true", help="port scan of a perticular host")
    parser.add_argument("-o", "--os", action= "store_true", help="detect the operating system a host is using")
    parser.add_argument("-p", "--pcap", action= "store_true", help="analysing of the present traffic")
    parser.add_argument("-t", "--target", help="specify target to scan")
    parser.add_argument("-f", "--file", default="Scrrappy.txt", help="specify which name to write findings to")
    args = parser.parse_args()
    
    scrappy = Scrappy(args)
    scrappy.run()

