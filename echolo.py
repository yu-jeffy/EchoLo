### Import necessary libraries ###
import scapy.all as scapy
import sys
import argparse
import os
import re
import platform
import socket
import json
from getmac import get_mac_address
from scapy.layers import http
from scapy.layers.inet import IP, ICMP, TCP, UDP, traceroute

# Function to get command line arguments
def get_arguments():
    parser = argparse.ArgumentParser(description='A Python-based network scanner with additional features')
    parser.add_argument('-t', '--target', dest='target', help='Target IP / IP Range', required=True)
    args = parser.parse_args()
    return args.target

# Function to perform ARP scan
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "interface": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list

# Function to get operating system from TTL value
def get_os(ip_address):
    ttl_values = {32: 'Windows', 64: 'Linux', 128: 'Windows', 255: 'Linux'}

    try:
        packet = IP(dst=ip_address) / ICMP()
        response = scapy.sr1(packet, timeout=1, verbose=0)
        if response:
            os = ttl_values.get(response[IP].ttl)
            if os:
                return os

    except Exception as e:
        # Exclude errors
        pass

# Function to perform port scan
def port_scan(ip, start_port=1, end_port=1024):
    open_ports = []
    closed_ports = []

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))

            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)

            sock.close()
        except KeyboardInterrupt:
            break

    return open_ports, closed_ports

# Function to print the scan results
def print_result(results_list):
    print("IP\t\t\tMAC Address\t\t\tOS\tInterface")
    print("---------------------------------------------------------------")

    for client in results_list:
        ip = client["ip"]
        mac = client["mac"]
        os = get_os(ip)
        if os: client["os"] = os
        print(f"{ip}\t\t{mac}\t\t{client.get('os', 'N/A')}\t\t{client['interface']}")

# Main function
def main():
    target_ip = get_arguments()
    scanned_output = scan(target_ip)
    print_result(scanned_output)

    for client in scanned_output:
        ip = client["ip"]
        traceroute_output = scapy.traceroute(ip)
        print(f"Traceroute to {ip}:")
        print(traceroute_output)

        open_ports, closed_ports = port_scan(ip)
        print(f"Open ports for {ip}: {open_ports}")
        print(f"Closed ports for {ip}: {closed_ports}")

# Start of the script
if __name__ == '__main__':
    main()
