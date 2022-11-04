# Scrappy
scrappy, een tool gebaseerd op de library scapy.
Deze tool heeft een aantal features:

## 1. discover hosts
In deze feature gaan we een netwerkrange (bv 192.168.1.1/24) scannen naar levende hosts.
We kunnen dit op meerdere manieren doen. Het verschil hier is het protocol je gebruikt.

- ICMP ping   
    ! Veel firewalls blokkeren tegenwoordig ICMP pakketten.
- UDP ping   
- TCP ping   
    ! gebruik van zowel syn als ack ping in combinatie.        
- IP Protocol ping
- ARP ping
pingen met het ARP protocol is sneller en meer betrouwbaar dan andere protocollen

## 2. discover services
We sturen paketjes naar de verschillende poorten van een host.
Aan de hand van het antwoord, kunnen we zien of deze poort al dan niet open staat.

## 3. Remote OS detection
Linux en Windows hebben verschillende time to life op hun icmp pakketen.
We kijken dus naar de ttl in het antwoordpakket van onze host.

## 4. PCAP analyse
In dit deel gaan we het netwekr afscannen naar HTTP verkeer.