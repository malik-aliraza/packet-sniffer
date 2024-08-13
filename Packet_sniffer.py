import socket
import struct
import textwrap

TAB_1 = '\t'
TAB_2 = '\t\t'

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # type: ignore
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print(TAB_1 + f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")
        if eth_proto == 0x0800:  # IPv4
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(TAB_2 + f'Protocol: {proto}, Source: {src}, Target: {target}')

            if proto == 1:  # ICMP
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')

            elif proto == 6:  # TCP
                src_port, dst_port, sequence, acknowledge, flags, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dst_port}')
                print(TAB_2 + f'Sequence: {sequence}, Acknowledge: {acknowledge}')
                print(TAB_2 + 'Flags:')
                print(TAB_2 + f'URG: {flags["urg"]}, ACK: {flags["ack"]}, PSH: {flags["psh"]}')
                print(TAB_2 + f'RST: {flags["rst"]}, SYN: {flags["syn"]}, FIN: {flags["fin"]}')

            elif proto == 17:  # UDP
                src_port, dst_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dst_port}, Length: {length}')

def ethernet_frame(data):
    destination_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(proto), data[14:]

def get_mac_address(bytes_mac):
    bytes_str = map('{:02x}'.format, bytes_mac)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    src_port, dst_port, sequence, acknowledge, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    flags = {'urg': flag_urg, 'ack': flag_ack, 'psh': flag_psh, 'rst': flag_rst, 'syn': flag_syn, 'fin': flag_fin}
    return src_port, dst_port, sequence, acknowledge, flags, data[offset:]

def udp_segment(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dst_port, size, data[8:]

if __name__ == '__main__':
    main()
