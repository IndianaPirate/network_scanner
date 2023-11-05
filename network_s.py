#!/usr/bin/python3

import scapy.all as scapy
import argparse


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP range")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=10)[0]
    client_list = []
    for elem in answered:
        client = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
        client_list.append(client)
    return client_list

def display(result):
    print("IP\t\t\tMAC Address\n------------------------------------------------")
    for client in result:
        print(client["ip"]+"\t\t"+client["mac"])

options = arguments()
result = scan(options.target)
display(result)