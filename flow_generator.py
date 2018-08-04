# Simple flow generator for testing and benchmarking the flow management system



from scapy.all import *
import random
import sys
import argparse

if len(sys.argv) < 9:
    print len(sys.argv)
    print ("Invalid arguments")
    print ("Usage : python genereate_packets.py -ip IP -proto icmp/tcp/udp -port 1000-2000 -packets 50")
    sys.exit(0)

ip = sys.argv[2]
proto = sys.argv[4]
port_start = int(sys.argv[6].split("-")[0])
port_end = int(sys.argv[6].split("-")[1])
packets = int(sys.argv[8])
port_list = random.sample(range(port_start,port_end), packets)

if proto == "tcp":
    send(IP(dst=ip)/TCP(dport=port_list))
elif proto == "udp":
    send(IP(dst=ip)/UDP(dport=port_list))
else:
    send(IP(dst=ip)/ICMP())
