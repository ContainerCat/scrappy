# Scrappy
scrappy is a tool based on the library "scapy".
This tool has a few base features.

## features
### 1. Discover hosts
This feature will scan a network range for living hosts.
This can be done in multiple ways:

- ICMP ping   
    ! A lot of firewalls block ICMP packets.
- UDP ping   
- TCP ping   
- IP Protocol ping   
- ARP ping   
    pinging with the ARP protocol is faster and more reliable than the other protocols

### 2. Discover services
To discover services running on a host, we will send packages to the different ports.
Looking at the (lack of) answer, will clarify the status of a port.
We scan all ports from 1 to 1024.

### 3. Remote OS detection
Linux kernel and Windows have different time to life in their ICMP packets.
We can extract this from the answer on our sent ICMP packet.

### 4. PCAP analyse
We analyse and scan the network for HTTP trafic.
You can do this for a particular host and for a network range

## getting started
Install [Scapy](https://scapy.net)
```
git clone https://github.com/secdev/scapy.git
cd scapy
sudo python setup.py install
```

Clone this repository
```
git clone git@github.com:vanHooijdonkC/scrappy.git
```

Run help command to see all options
```
python scrappy.py -h
```
