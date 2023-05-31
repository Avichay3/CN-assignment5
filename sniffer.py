from socket import ntohs, SOCK_RAW, inet_ntoa, socket, AF_PACKET
from struct import unpack
from time import time

output_file = '2117.txt'

def packetSniffer(packet):
    eth_header = packet[:14]
    ip_header = packet[14:34]
    protocol = ip_header[9]

    if protocol == 6:  # TCP
        tcp_header = packet[34:54]
        payload = packet[54:]

        eth_fields = unpack("!6s6sH", eth_header)
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

        data = payload.hex()

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
