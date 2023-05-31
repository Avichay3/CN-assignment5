from socket import ntohs, SOCK_RAW, inet_ntoa, socket, AF_PACKET
from struct import unpack
from time import time

output_file = '2117.txt'

def packetSniffer(packet):
    ethernet_header = packet[:14]  # consist of the first 14 bytes that extracted from the packet
    ip_header = packet[14:34]  # consist of the 15th byte and extends to the 34th byte
    protocol = ip_header[9]  # extracted from the ip header at the 10th byte which is index 9

    if protocol == 6:  # TCP protocol, got it from https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        tcp_header = packet[34:54]  # consist of the 35th byte and extends to the 54th byte
        payload_data = packet[54:]  # extracted from the packet, starting from the 55th byte

        eth_fields = unpack("!6s6sH", ethernet_header)
        source_mac = ':'.join('%02x' % b for b in eth_fields[0])
        dest_mac = ':'.join('%02x' % b for b in eth_fields[1])

        ip_fields = unpack("!BBHHHBBH4s4s", ip_header)
        source_ip = inet_ntoa(ip_fields[8])
        dest_ip = inet_ntoa(ip_fields[9])

        tcp_fields = unpack("!HHLLBBHHH", tcp_header)
        source_port = tcp_fields[0]
        dest_port = tcp_fields[1]

        timestamp = int(time())
        total_length = ip_fields[2]
        cache_flag = 0
        steps_flag = 0
        type_flag = 0
        status_code = 0
        cache_control = 0

        data = payload_data.hex()

        output = f"source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, " \
                 f"dest_port: {dest_port}, timestamp: {timestamp}, total_length: {total_length}, " \
                 f"cache_flag: {cache_flag}, steps_flag: {steps_flag}, type_flag: {type_flag}, " \
                 f"status_code: {status_code}, cache_control: {cache_control}, data: {data}\n"

        with open(output_file, "a") as f:
            f.write(output)


# Create a raw socket and bind it to the network interface
s = socket(AF_PACKET, SOCK_RAW, ntohs(3))

# Enable promiscuous mode to capture all packets
s.bind(('your_network_interface', 0))

# Sniff packets indefinitely
while True:
    packet = s.recvfrom(65565)
    packetSniffer(packet[0])
