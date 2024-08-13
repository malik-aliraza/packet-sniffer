from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_handler(packet):
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f'\nEthernet Frame:')
        print(f'\tDestination MAC: {eth.dst}, Source MAC: {eth.src}, Type: {eth.type}')

        if eth.type == 0x0800:  # IPv4
            if packet.haslayer(IP):
                ip = packet[IP]
                print(f'\tIPv4 Packet:')
                print(f'\t\tVersion: {ip.version}, Header Length: {ip.ihl}, TTL: {ip.ttl}')
                print(f'\t\tProtocol: {ip.proto}, Source: {ip.src}, Destination: {ip.dst}')

                if ip.proto == 1 and packet.haslayer(ICMP):  # ICMP
                    icmp = packet[ICMP]
                    print(f'\t\tICMP Packet:')
                    print(f'\t\t\tType: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.chksum}')

                elif ip.proto == 6 and packet.haslayer(TCP):  # TCP
                    tcp = packet[TCP]
                    print(f'\t\tTCP Segment:')
                    print(f'\t\t\tSource Port: {tcp.sport}, Destination Port: {tcp.dport}')
                    print(f'\t\t\tSequence Number: {tcp.seq}, Acknowledgment Number: {tcp.ack}')
                    print(f'\t\t\tFlags:')
                    print(f'\t\t\t\tURG: {tcp.flags.U}, ACK: {tcp.flags.A}, PSH: {tcp.flags.P}')
                    print(f'\t\t\t\tRST: {tcp.flags.R}, SYN: {tcp.flags.S}, FIN: {tcp.flags.F}')

                elif ip.proto == 17 and packet.haslayer(UDP):  # UDP
                    udp = packet[UDP]
                    print(f'\t\tUDP Segment:')
                    print(f'\t\t\tSource Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}')

if __name__ == "__main__":
    print("Starting packet sniffer...")
    sniff(prn=packet_handler, store=0)
