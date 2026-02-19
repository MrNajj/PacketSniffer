# sniffer - A network traffic analyzer for educational purposes
# Copyright (C) 2026 Ahmad Al Najjar
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from collections import defaultdict
import socket
import requests


captured_packets = []
ip_traffic = defaultdict(int)
protocol_count = {"TCP": 0, "UDP": 0, "DNS": 0, "Other": 0}

# let user pick how many packets they want to see
try:
    numPackets = int(input("How many packets (number) do you want to analyze: "))
except ValueError:
    print("Invalid input, defaulting to 50 packets.")
    numPackets = 50

# -----------------------------------------
# IP HELPERS
# -----------------------------------------

# A method that finds who is behind the IP, resolve the IP
def resolve_ip(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return ip  #just return the raw IP, if cant find who is behind the IP
    
# a method that finds the geolocation of the IP
def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        data = response.json()
        if data["status"] == "success":
            return f"{data['city']}, {data['country']}"
        else:
            return "Unknown"
    except:
        return "Unknown"


# -----------------------------------------
# PACKET HOLDER
# -----------------------------------------
def packet_holder(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        ip_traffic[source] +=1
        
        print("=" * 60)
        
        # explain what has been sniffed/captured
        print(f"  Protocol : {explain_protocol(packet)}")
        print(f"  Source   : {resolve_ip(source)} || {get_location(source)}")
        print(explain_ip(source))
        print(f"  Dest     : {resolve_ip(destination)} | {get_location(destination)}")
        print(explain_ip(destination))
        
        
        
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"  Source - Src Port : {explain_port(sport)}")
            print(f"  Destination - Dst Port : {explain_port(dport)}")
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"  Source - Src Port : {explain_port(sport)}")
            print(f"  Destination - Dst Port : {explain_port(dport)}")
            
        if DNS in packet and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode()
            print(f"  DNS Query: {query}")
            print(f"  --> Your device is asking 'what is the IP address for {query}'")


        print()
        captured_packets.append(packet)
    
    
# -----------------------------------------
# EXPLAINER FUNCTIONS
# -----------------------------------------
def explain_ip(ip):
    if ip.startswith("10.") or ip.startswith("192.168."):
        return f"  --> {ip} is a PRIVATE IP - a device on your local network (phone, laptop, smart TV, etc.)"
    elif ip.startswith("127."):
        return f"  --> {ip} is a LOOPBACK address - your machine talking to itself"
    elif ip == "255.255.255.255":
        return f"  --> {ip} is a BROADCAST address - a device shouting to the entire network (common for device discovery)"
    elif ip == "239.255.255.250":
        return f"  --> {ip} is a MULTICAST address - devices announcing themselves (Smart TVs, Chromecast, printers do this constantly)"
    elif ip.startswith("169.254."):
        return f"  --> {ip} is a LINK-LOCAL address - often a router, VPN adapter, or a device that could not get a proper IP"
    elif ip.startswith("104.16.") or ip.startswith("104.17.") or ip.startswith("104.18.") or ip.startswith("104.19."):
        return f"  --> {ip} is a CLOUDFLARE IP - a website you are visiting is routed through Cloudflare's network"
    elif ip.startswith("8.8."):
        return f"  --> {ip} is GOOGLE DNS - your device is looking up a domain name"
    elif ip.startswith("1.1."):
        return f"  --> {ip} is CLOUDFLARE DNS - your device is looking up a domain name"
    else:
        return f"  --> {ip} is a PUBLIC IP - a server somewhere on the internet"

def explain_port(port):
    port_map = {
        80:   "HTTP   - unencrypted web traffic",
        443:  "HTTPS  - encrypted web traffic (secure)",
        53:   "DNS    - translating a domain name to an IP address",
        22:   "SSH    - secure remote login",
        25:   "SMTP   - sending email",
        143:  "IMAP   - receiving email",
        3306: "MySQL  - database connection",
        8080: "HTTP alternate - often a local dev server or proxy",
        8009: "Chromecast control port - a Google/Cast device on your network",
        5353: "mDNS   - local device discovery (Bonjour/Airplay)",
    }
    return port_map.get(port, f"Port {port} - ephemeral/application port (dynamically assigned)")

def explain_protocol(packet):
    if TCP in packet:
        return "TCP - reliable, ordered delivery (used for web, email, most apps)"
    elif UDP in packet:
        return "UDP - fast, connectionless delivery (used for DNS, streaming, gaming)"
    return "Unknown protocol"


        
# -----------------------------------------
# RUN
# -----------------------------------------

# Capture as much as user wants of packets
print("Starting capture... (ctrl+c to stop early)\n")
sniff(prn=packet_holder, store=False, filter="ip", count = numPackets)

print("\n========== SUMMARY ==========")
print(f"Total Packets Captured: {len(captured_packets)}")
print(f"\nTop Talkers:")
sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)
for ip, count in sorted_ips[:5]:
    print(f"  {resolve_ip(ip)} | {get_location(ip)} | {count} packets")