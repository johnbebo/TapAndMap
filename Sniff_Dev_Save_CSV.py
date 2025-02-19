#!/usr/bin/python3

# These are needed to sniff packets
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.layers.inet import ICMP

# This is needed to add the time
from datetime import datetime, timedelta
import datetime
import time

# This is needed to get lat/long/address, etc from IP address
import geoip2.database

# This is needed to clean up files
import os

IPsToIgnore = ""  # This should now be globally accessable.   I will set it in the TapAndMap.conf reader, and use it when writing packets
PacketCounter = 0 # This will count the number of packets stored
chksrc = ""
chkdst = ""

if os.path.exists("/tmp/tempfile"):
    os.remove("/tmp/tempfile")

# Read in TapAndMap.conf file and find IP Subnets to ignore and how often to split logs (might as well not even print those)
Config_F = open("/var/www/TapAndMap.conf", 'r')
for line in Config_F:
    if "IgnoreIPs" in line:
        IPsToIgnore = str(line)
    elif "LogRun" in line:
        LogRun = int(line[line.find('{')+1:line.rfind('}')])
Config_F.close()
#print("IPs to filter are: " + str(IPsToIgnore))
IPsToIgnore = IPsToIgnore[IPsToIgnore.find('{')+1:IPsToIgnore.rfind('}')]
IgnoreIPValues = IPsToIgnore.split(" ")
print("IPs to filter are: " + str(IPsToIgnore))
for item in IgnoreIPValues:
	chksrc = chksrc + 'src.startswith("' + item + '") or ' 
	chkdst = chkdst + 'dst.startswith("' + item + '") or ' 
srclen = len(chksrc)
dstlen = len(chkdst)
chksrc = chksrc[0:srclen - 3]
chkdst = chkdst[0:dstlen - 3]
#print ("chksrc line is: " + chksrc + '\n')
#print ("chkdst line is: " + chkdst + '\n')

DATABASE_PATH = '/home/pi/TapAndMap/GeoDB/GeoLite2-City_20250207/GeoLite2-City.mmdb'

# Define a callback function to process captured packets
def packet_handler(packet):
    global PacketCounter
    global FilterThese
    public = False
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        src_port = ""
        dst_port = ""
        proto = ""
        remote_lat = "NA"
        remote_long = "NA"
        remote_city = "NA"
        remote_country = "NA"
        remote_zip = "NA"
        if TCP in packet:
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
            proto = "TCP"
            #print(f"Destination IP: {ip_dst}, Destination Port (TCP): {port_dst}")
        elif UDP in packet:
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
            proto = "UDP"
            #print(f"Destination IP: {ip_dst}, Destination Port (UDP): {port_dst}")
        elif ICMP in packet:
            src_port = str(packet[ICMP].type)
            dst_port = str(packet[ICMP].type)
            proto = "ICMP"
        else:
            #print(f"Destination IP: {ip_dst}, Transport Layer: Other")
            src_port = "NA"
            dst_port = "NA"
            proto = "NA"
        # Now that the packet is defined, find if either source or destination is public, and if so, add data
        src = source_ip
        dst = dest_ip
        if not (eval(chksrc)):  # Source IP is public.  Get it's lat, long, country code, zip, city, and country, and set the destination to local values
            #print("Source IP of " + source_ip + " is public")
            public = True
            with geoip2.database.Reader(DATABASE_PATH) as reader:
                try:
                    response = reader.city(source_ip)
                    remote_lat = response.location.latitude
                    remote_long = response.location.longitude
                    remote_city = response.city.name
                    remote_country = response.country.name
                    remote_zip = response.postal.code
                except geoip2.errors.AddressNotFoundError:
                    print(f"No Location Found for IP:  {source_ip}")
                    public = False
        elif not (eval(chkdst)): # Destination IP is public.  Get it's lat, long, country code, zip, city, and country, and set the destination to local values
            #print("Dest IP of " + dest_ip + " is public")
            public = True
            with geoip2.database.Reader(DATABASE_PATH) as reader:
                try:
                    response = reader.city(dest_ip)
                    remote_lat = response.location.latitude
                    remote_long = response.location.longitude
                    remote_city = response.city.name
                    remote_country = response.country.name
                    remote_zip = response.postal.code
                except geoip2.errors.AddressNotFoundError:
                    print(f"No Location Found for IP:  {dest_ip}")
                    public = False
        if remote_city == None:
            remote_city = "UNK"
        if remote_country == None:
            remote_country = "UNK"
        if remote_zip == None:
            remote_zip == "UNK"
        if public == True:  # Only write packets if one end or the other is public
            PacketCounter = PacketCounter +1
            now = datetime.datetime.now()
            fnow = now.strftime("%Y-%m-%d %H:%M:%S")
            print(str(PacketCounter) + "," + fnow + "," + source_ip + ":" + src_port + "," + dest_ip + ":" + dst_port + "," + proto + "," + str(remote_lat) + "," + str(remote_long) + "," + remote_city + "," + remote_country + "," + str(remote_zip) + "\n")
            f = open("/tmp/tempfile", 'a')
            #print(packet.summary())  #Print a brief summary of each packet
            #f.write(packet.summary() + "\n")
            f.write(str(PacketCounter) + "," + fnow + "," + source_ip + ":" + src_port + "," + dest_ip + ":" + dst_port + "," + proto + "," + str(remote_lat) + "," + str(remote_long) + "," + remote_city + "," + remote_country + "," + str(remote_zip) + "\n")
            f.close()

# Sniff packets on the specified interface in promiscuous mode
def start_sniffing(interface):
    print(f"Sniffing on interface {interface} in promiscous mode...")
    sniff(iface=interface, prn=packet_handler, store=False)

#Change 'eth0' to your network interface
if __name__ == "__main__":
    start_sniffing("eth1")