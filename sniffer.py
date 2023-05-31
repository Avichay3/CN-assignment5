from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.inet import ICMP, UDP, TCP, IP


def process_tcp_packet(packet):
    """"
    This function as her name says, process TCP packets.
    We extract some information (source_ip, destination_ip...).
    """
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport
    timestamp = packet.time
    total_length = len(packet)
    cache_flag = packet.getlayer(Raw).load


    # write the extracted data to the output file
    with open("output.txt", "a") as file:
        file.write(f"{{ source_ip: {source_ip}, dest_ip: {destination_ip}, source_port: {source_port}, dest_port: {destination_port}, protocol: TCP, timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag.hex()}, data: {packet.payload.hex()} }}\n")

def process_udp_packet(packet):
    """
    This function as her name says, process UDP packets.
    Overall, this function do as the function above but for UDP protocol
    """
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    source_port = packet[UDP].sport
    destination_port = packet[UDP].dport
    timestamp = packet.time
    total_length = len(packet)

    with open("output.txt", "a") as file:
        file.write(f"{{ source_ip: {source_ip}, dest_ip: {destination_ip}, source_port: {source_port}, dest_port: {destination_port}, protocol: UDP, timestamp: {timestamp}, total_length: {total_length}, data: {packet.payload.hex()} }}\n")

def process_icmp_packet(packet):
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    timestamp = packet.time
    total_length = len(packet)

    with open("output.txt", "a") as file:
        file.write(f"{{ source_ip: {source_ip}, dest_ip: {destination_ip}, protocol: ICMP, timestamp: {timestamp}, total_length: {total_length}, data: {packet.payload.hex()} }}\n")

def process_igmp_packet(packet):
    # IGMP packet processing logic goes here
    pass

def process_raw_packet(packet):
    # RAW packet processing logic goes here
    pass

def process_packet(packet):
    if IP in packet:
        if TCP in packet:
            process_tcp_packet(packet)
        elif UDP in packet:
            process_udp_packet(packet)
        elif ICMP in packet:
            process_icmp_packet(packet)
        elif IGMP in packet:
            process_igmp_packet(packet)
        else:
            process_raw_packet(packet)

# Capture packets and process them
sniff(filter="", prn=process_packet)
