#!/usr/bin/env python3
import socket
import struct
from struct import *
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data=raw_data)
        print('\nEthernet Frame')
        print(f'Destination: {eth[0]}, Source: {eth[1]}, Protocol: {eth[2]}')
        if eth[2] == 8:
            ipv4 = ipv4_head(raw_data=eth[3])
            print(f'{TAB_1}IPv4 Packet:')
            print(f'{TAB_2}Version: {ipv4[0]}, Header Length: {ipv4[1]}, TTL: {ipv4[2]}')
            print(f'{TAB_2}Protocol: {ipv4[3]}, Source: {ipv4[4]}, Target: {ipv4[5]}')

            if ipv4[3] == 1:
                icmp_type, code, checksum, data = icmp_head(raw_data=ipv4[6])
                print(f'{TAB_1}ICMP Packet')
                print(f'{TAB_2}Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(f'{TAB_2}Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif ipv4[3] == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flack_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_head(raw_data=ipv4[6])
                print(f'{TAB_1}TCP Segment:')
                print(f'{TAB_2}Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'{TAB_2}Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'{TAB_2}Flags:')
                print(f'{TAB_3}URG: {flag_urg}, ACK: {flack_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(f'{TAB_2}Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif ipv4[3] == 17:
                src_port, dest_port, size, data = udp_head(raw_data=ipv4[6])
                print(f'{TAB_1}UDP Segment:')
                print(f'{TAB_2}Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}')
                print(f'{TAB_2}Data:')
                print(format_multi_line(DATA_TAB_3, data))

            else:
                print(f'{TAB_1}Data:')
                print(format_multi_line(TAB_2, ipv4[6]))
        else:
            print(f'{TAB_1}Data:')
            print(format_multi_line(TAB_2, eth[3]))

def get_ip(addr):
    return '.'.join(map(str, addr))

def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype) #fix this
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def get_mac_addr(addr):
    return ':'.join(map('{:02x}'.format, addr)).upper()

def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src)
    target = get_ip(target)
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data

def tcp_head(raw_data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flack_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3 
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags &  1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flack_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def icmp_head(raw_data):
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    return icmp_type, code, checksum, raw_data[4:]

def udp_head(raw_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
    return src_port, dest_port, size, raw_data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf
# https://github.com/LinuxTeam-teilar/python-sniffer/blob/master/functs.py
# https://www.youtube.com/watch?v=3zwuOo7U1YQ&list=PL6gx4Cwl9DGDdduy0IPDDHYnUx66Vc4ed&index=5&ab_channel=thenewboston



if __name__=="__main__":
    main()