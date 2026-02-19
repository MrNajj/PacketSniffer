# PacketSniffer

## Intro
Every time you visit a website, stream a video, oe send a message, your computer is constantly sending and receiving chunks of data called packets. These packets travel across the internet through your devices and servers around the world, and you usually would never see them. 

## What the PacketSniffer achieves  
This program makes that traffic which is invisible to the user visible. The project sits in the background and watches/sniffs every packet moving in and out of your machine in live time.
Every packet it catches it breaks it down and explain its details in plain english.
- where the data is coming from (Source)
- where the data is going (Destination)
- Type of data it is (IP, TCP, UDP, DNS, DNSQR)
- Geo-location (city or country) of the destination server is located in

## How to run PacketSniffer

This program is built on Python and extensively uses the 'Scapy' library and also uses the 'Requests' library. So you will need python installed on your machine.

### Install dependencies
```
pip3 install scapy requests
```
OR 
```
python3 -m pip install scapy requests
```

### Run the Program
Make sure you are on a terminal that is on the same level of sniffer.py and beacuse this program accesses raw network data, it must be run with administrator privileges:
```
sudo python3 PacketSniffer.py
```

NOTE: You will be prompted to enter your system password — this is normal and required.

### Usage
Once running, you will be asked how many packets you want to capture:
```
How many packets (number) do you want to analyze: 50
```
Type a number and press Enter. Press `Ctrl + C` at any time to stop early and jump to the summary.


# IMPORTANT
This tool is only for education use and should not be used for obtaining sensitive information that you are not expected to obtain. And is meant to ran on your own machine and your own network

While this program was built with good intentions, it is important to be transparent about how it could be abused:

- **Spying on others** — if someone ran this on a shared or public network, they could monitor the traffic of other users on that network without their knowledge
- **Credential harvesting** — on unencrypted connections (HTTP, port 80), a modified version of this tool could be used to intercept usernames, passwords, and other sensitive data sent in plain text
- **Device mapping** — the program reveals every device on your network, their IP addresses, and their activity patterns, which could be used maliciously to identify targets
- **Data collection** — the captured packets and geolocation data could be logged and used to build a profile of someone's browsing habits and online behavior

This tool does not decrypt HTTPS traffic, see beyond your own network, does not make you anonymous

All the tools that have been used for this python script is all open sourced and extensively documented.
References: Claude GenAI assistant to help with explaining the different IP addresses and writing code to provide text on terminal about those IP addresses. 

# License
This project is licensed under the GNU General Public License v3.0. 
See the [LICENSE](LICENSE) file for details.
