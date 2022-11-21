from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore
import argparse

init()

red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
yellow = Fore.YELLOW
reset = Fore.RESET

argparse = argparse.ArgumentParser(prog = 'Sinfing Packets',description = 'This is tool is Basically snif the Packets.',usage='python3 htsnifing.py -i interface')
argparse.add_argument("-i","--iface",help="Enter The interface name where you want to snif the packets")
argparse.add_argument("-p","--protocol",help="Enter The protocol Name <http/all(http/tcp/ip)>.")
args = argparse.parse_args()
protocol = args.protocol

def sniff_packets(iface):
    if iface:
        sniff(filter = 'dst port 80', prn = process_packet, iface = iface, store=False)
    else:
        sniff(prn = process_packet, store = False)

def process_packet(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f"{blue}[+] {src_ip} is using port {src_port} to connect to {dst_ip} at {dst_port}{reset}")
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"{green}[+] {src_ip} is making a HTTP request to {url} with method {method}")
        if(protocol == 'all'):
            print(f"[+] HTTP Data:")
            print(f"{yellow} {packet[''].show()}")
        elif(protocol == 'http'):
            print(f"[+] HTTP Data:")
            print(f"{yellow} {packet[HTTPRequest].show()}")
        else:
            print(f"{red} [-] Error Provided value is Not availavail.")
    if packet.haslayer(Raw):
        print(f"{red}[+] Useful raw Data: {packet.getlayer(Raw).load.decode()}{reset}")


iface = args.iface
sniff_packets(iface)


